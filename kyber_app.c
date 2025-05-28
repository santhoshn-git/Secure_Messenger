#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <oqs/kem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

#define MSG_LEN 256
#define AES_KEY_LEN 32
#define AES_BLOCK_SIZE 16

GtkWidget *entry_sender, *entry_receiver, *entry_message;
GtkWidget *text_view_output;
GtkTextBuffer *buffer_output;
GtkWidget *file_chooser;
GtkWidget *checkbox_encrypt_audio;
GtkWidget *label_status;
GtkWidget *button_play_audio;

char decrypted_audio_path[] = "decrypted_audio.wav";

long get_time_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000000L + tv.tv_usec);
}

int encrypt(const EVP_CIPHER *cipher, const unsigned char *plaintext, int plaintext_len,
            const unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(const EVP_CIPHER *cipher, const unsigned char *ciphertext, int ciphertext_len,
            const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

unsigned char *read_file(const char *filename, size_t *length) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    *length = ftell(fp);
    rewind(fp);
    unsigned char *buffer = malloc(*length);
    fread(buffer, 1, *length, fp);
    fclose(fp);
    return buffer;
}

int write_file(const char *filename, const unsigned char *data, size_t length) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;
    fwrite(data, 1, length, fp);
    fclose(fp);
    return 0;
}

void append_output(const char *message) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer_output, &end);
    gtk_text_buffer_insert(buffer_output, &end, message, -1);
    gtk_text_buffer_insert(buffer_output, &end, "\n", -1);
}

void play_audio(const char *file_path) {
    FILE *fp = fopen("/proc/sys/kernel/osrelease", "r");
    int is_wsl = 0;
    if (fp) {
        char buffer[256];
        fread(buffer, 1, sizeof(buffer) - 1, fp);
        buffer[255] = '\0';
        if (strstr(buffer, "Microsoft") || strstr(buffer, "microsoft")) {
            is_wsl = 1;
        }
        fclose(fp);
    }

    char command[512];
    if (is_wsl) {
        snprintf(command, sizeof(command), "powershell.exe /c start '%s'", file_path);
    } else {
        snprintf(command, sizeof(command), "aplay '%s' &", file_path);
    }
    system(command);
}

void on_play_audio_clicked(GtkWidget *widget, gpointer data) {
    play_audio(decrypted_audio_path);
}

void print_hex(const char *label, const unsigned char *data, size_t len, char *output, size_t output_size) {
    char *ptr = output;
    int offset = snprintf(ptr, output_size, "%s: ", label);
    ptr += offset;
    output_size -= offset;

    for (size_t i = 0; i < len && output_size > 2; i++) {
        offset = snprintf(ptr, output_size, "%02X", data[i]);
        ptr += offset;
        output_size -= offset;
    }
    snprintf(ptr, output_size, "\n");
}

void on_encrypt_clicked(GtkWidget *widget, gpointer data) {
    const gchar *sender = gtk_entry_get_text(GTK_ENTRY(entry_sender));
    const gchar *receiver = gtk_entry_get_text(GTK_ENTRY(entry_receiver));
    const gchar *message = gtk_entry_get_text(GTK_ENTRY(entry_message));
    gboolean encrypt_audio = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(checkbox_encrypt_audio));

    if (strlen(sender) == 0 || strlen(receiver) == 0 || (strlen(message) == 0 && !encrypt_audio)) {
        append_output("Please fill all fields or select an audio file.");
        return;
    }

    OQS_KEM *kem = OQS_KEM_new("Kyber1024");
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext_kem = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_sender = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_receiver = malloc(kem->length_shared_secret);

    long kgen_start = get_time_microseconds();
    OQS_KEM_keypair(kem, public_key, secret_key);
    long kgen_end = get_time_microseconds();

    long enc_start = get_time_microseconds();
    OQS_KEM_encaps(kem, ciphertext_kem, shared_secret_sender, public_key);
    long enc_end = get_time_microseconds();

    long dec_start = get_time_microseconds();
    OQS_KEM_decaps(kem, shared_secret_receiver, ciphertext_kem, secret_key);
    long dec_end = get_time_microseconds();

    if (memcmp(shared_secret_sender, shared_secret_receiver, kem->length_shared_secret) != 0) {
        append_output("Shared secret mismatch.");
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    char buffer[8192];
    char hex_output[2048];

    if (!encrypt_audio) {
        unsigned char ciphertext[MSG_LEN + AES_BLOCK_SIZE];
        unsigned char decrypted[MSG_LEN + AES_BLOCK_SIZE];

        long aes_enc_start = get_time_microseconds();
        int cipher_len = encrypt(EVP_aes_256_cbc(), (unsigned char *)message, strlen(message), shared_secret_sender, iv, ciphertext);
        long aes_enc_end = get_time_microseconds();

        long aes_dec_start = get_time_microseconds();
        int plain_len = decrypt(EVP_aes_256_cbc(), ciphertext, cipher_len, shared_secret_receiver, iv, decrypted);
        long aes_dec_end = get_time_microseconds();
        decrypted[plain_len] = '\0';

        print_hex("Ciphertext", ciphertext, cipher_len, hex_output, sizeof(hex_output));
        char iv_hex[128];
        print_hex("IV", iv, AES_BLOCK_SIZE, iv_hex, sizeof(iv_hex));

        snprintf(buffer, sizeof(buffer),
                 "[ENCRYPTED TEXT] from %s to %s\nOriginal: %s\nDecrypted: %s\n\nKeyGen: %ld us\nKyber Encaps: %ld us\nKyber Decaps: %ld us\nAES Encrypt: %ld us\nAES Decrypt: %ld us\n\n%s%s",
                 sender, receiver, message, decrypted,
                 kgen_end - kgen_start,
                 enc_end - enc_start,
                 dec_end - dec_start,
                 aes_enc_end - aes_enc_start,
                 aes_dec_end - aes_dec_start,
                 hex_output, iv_hex);
    } else {
        const gchar *file_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
        if (!file_path) {
            append_output("No audio file selected.");
            return;
        }

        size_t input_len;
        unsigned char *input_data = read_file(file_path, &input_len);
        unsigned char *encrypted_data = malloc(input_len + AES_BLOCK_SIZE);
        unsigned char *decrypted_data = malloc(input_len + AES_BLOCK_SIZE);

        long aes_enc_start = get_time_microseconds();
        int encrypted_len = encrypt(EVP_aes_256_cbc(), input_data, input_len, shared_secret_sender, iv, encrypted_data);
        long aes_enc_end = get_time_microseconds();

        write_file("encrypted_audio.dat", encrypted_data, encrypted_len);

        long aes_dec_start = get_time_microseconds();
        int decrypted_len = decrypt(EVP_aes_256_cbc(), encrypted_data, encrypted_len, shared_secret_receiver, iv, decrypted_data);
        long aes_dec_end = get_time_microseconds();
        write_file(decrypted_audio_path, decrypted_data, decrypted_len);

        print_hex("Ciphertext", encrypted_data, encrypted_len, hex_output, sizeof(hex_output));
        char iv_hex[128];
        print_hex("IV", iv, AES_BLOCK_SIZE, iv_hex, sizeof(iv_hex));

        snprintf(buffer, sizeof(buffer),
                 "[ENCRYPTED AUDIO] from %s to %s\nEncrypted: encrypted_audio.dat\nDecrypted: %s\n\nKeyGen: %ld us\nKyber Encaps: %ld us\nKyber Decaps: %ld us\nAES Encrypt: %ld us\nAES Decrypt: %ld us\n\n%s%s",
                 sender, receiver, decrypted_audio_path,
                 kgen_end - kgen_start,
                 enc_end - enc_start,
                 dec_end - dec_start,
                 aes_enc_end - aes_enc_start,
                 aes_dec_end - aes_dec_start,
                 hex_output, iv_hex);

        free(input_data);
        free(encrypted_data);
        free(decrypted_data);
    }

    append_output(buffer);
    gtk_label_set_text(GTK_LABEL(label_status), "Encryption completed successfully.");

    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext_kem);
    free(shared_secret_sender);
    free(shared_secret_receiver);
}

void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *button_encrypt;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Secure Messaging - Kyber + AES");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 700);

    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(window), grid);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);

    entry_sender = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_sender), "Sender");
    gtk_grid_attach(GTK_GRID(grid), entry_sender, 0, 0, 2, 1);

    entry_receiver = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_receiver), "Receiver");
    gtk_grid_attach(GTK_GRID(grid), entry_receiver, 0, 1, 2, 1);

    entry_message = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_message), "Enter your message...");
    gtk_grid_attach(GTK_GRID(grid), entry_message, 0, 2, 2, 1);

    file_chooser = gtk_file_chooser_button_new("Choose Audio File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_grid_attach(GTK_GRID(grid), file_chooser, 0, 3, 2, 1);

    checkbox_encrypt_audio = gtk_check_button_new_with_label("Encrypt Audio File");
    gtk_grid_attach(GTK_GRID(grid), checkbox_encrypt_audio, 0, 4, 2, 1);

    button_encrypt = gtk_button_new_with_label("Encrypt & Send");
    gtk_grid_attach(GTK_GRID(grid), button_encrypt, 0, 5, 2, 1);

    GtkWidget *label_output = gtk_label_new("Output:");
    gtk_grid_attach(GTK_GRID(grid), label_output, 0, 6, 2, 1);

    text_view_output = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view_output), FALSE);
    buffer_output = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view_output));
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), text_view_output);
    gtk_widget_set_size_request(scroll, 580, 250);
    gtk_grid_attach(GTK_GRID(grid), scroll, 0, 7, 2, 1);

    button_play_audio = gtk_button_new_with_label("Play Decrypted Audio");
    gtk_grid_attach(GTK_GRID(grid), button_play_audio, 0, 8, 2, 1);

    label_status = gtk_label_new("");
    gtk_grid_attach(GTK_GRID(grid), label_status, 0, 9, 2, 1);

    g_signal_connect(button_encrypt, "clicked", G_CALLBACK(on_encrypt_clicked), NULL);
    g_signal_connect(button_play_audio, "clicked", G_CALLBACK(on_play_audio_clicked), NULL);

    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.SecureMessenger", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}