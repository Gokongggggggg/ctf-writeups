## main

``` c
int main(int argc, char **argv) {
    char *priv_mode;
    int opt = 1;
    int server_fd;
    int *client_fd;
    socklen_t client_addr_len;
    pthread_t thread_id;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    priv_mode = getenv("PRIV_MODE");
    if (priv_mode == NULL) {
        strncpy(PRIV_MODE, "OFF", 4);
    } else {
        if (strcmp(priv_mode, "ON") == 0) {
            strncpy(PRIV_MODE, "ON", 3);
        } else {
            strncpy(PRIV_MODE, "OFF", 4);
        }
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        perror("setsockopt");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1337);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        perror("bind");
        exit(1);
    }

    if (listen(server_fd, 10) != 0) {
        perror("listen");
        exit(1);
    }

    while (true) {
        client_addr_len = sizeof(client_addr);
        client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (*client_fd < 0) {
            free(client_fd);
            break;
        }
        
        pthread_create(&thread_id, NULL, handle_client, client_fd);
        pthread_detach(thread_id);
    }

    perror("accept");
    exit(1);
}
```

## init_ctx

``` c

void init_ctx(ctx_t *ctx, bool debug_mode) {
    if (debug_mode) {
        puts("init_ctx()");
    }
    
    // Clear the entire struct first
    memset(ctx, 0, 1000000); 
    
    // These specific memsets are redundant if the whole struct is zeroed,
    // but kept here to reflect the original logic/struct layout.
    memset(ctx->method, 0, 16);
    memset(ctx->route, 0, 128);
    memset(ctx->http_version, 0, 16);
    memset(ctx->filepath, 0, 128);
    memset(ctx->file_extension, 0, 36);      // 0x24
    memset(ctx->host_header, 0, 128);
    memset(ctx->user_agent_header, 0, 128);
    memset(ctx->accept_header, 0, 128);
    memset(ctx->accept_language_header, 0, 128);
    memset(ctx->accept_encoding_header, 0, 128);
    memset(ctx->connection_header, 0, 128);
    memset(ctx->status, 0, 16);
    memset(ctx->response, 0, 1000000);
    memset(ctx->mime_type, 0, 32);           // 0x20 (Target overflow)
    
    ctx->debug = debug_mode;
}

void get_mime_type(ctx_t *ctx) {
    if (ctx->debug) {
        puts("get_mime_type()");
    }

    if (strcasecmp(ctx->file_extension, "html") == 0 || strcasecmp(ctx->file_extension, "htm") == 0) {
        strncpy(ctx->mime_type, "text/html", 32);
    } 
    else if (strcasecmp(ctx->file_extension, "txt") == 0) {
        strncpy(ctx->mime_type, "text/plain", 32);
    } 
    else if (strcasecmp(ctx->file_extension, "jpg") == 0 || strcasecmp(ctx->file_extension, "jpeg") == 0) {
        strncpy(ctx->mime_type, "image/jpeg", 32);
    } 
    else if (strcasecmp(ctx->file_extension, "png") == 0) {
        strncpy(ctx->mime_type, "image/png", 32);
    } 
    else if (strcasecmp(ctx->file_extension, "pdf") == 0) {
        strncpy(ctx->mime_type, "application/pdf", 32);
    } 
    else {
        // VULNERABILITY: 36 bytes (0x24) copied into a 32 byte (0x20) buffer.
        // The extra 4 bytes will overwrite the adjacent memory (ctx->debug).
        memcpy(ctx->mime_type, ctx->file_extension, 36);
    }
}


```

## Handle_Client

``` c
void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    ssize_t bytes_received;
    ctx_t ctx_on_stack;

    init_ctx(&ctx_on_stack, false);

    bytes_received = recv(client_fd, &ctx_on_stack, 1000000, 0);

    if (ctx_on_stack.debug) {
        printf("bytes_received = %ld\n", bytes_received);
        printf("Client fd = %d\n", client_fd);
        printf("Received %ld bytes from client\n", bytes_received);
        printf("Request:\n%s", (char *)&ctx_on_stack);
    }

    if (bytes_received == 0) {
        build_bad_http_response(&ctx_on_stack);
    } else {
        parse_request_line(&ctx_on_stack);

        if (ctx_on_stack.debug) {
            printf("method = %s\nroute = %s\nhttp version = %s\n",
                   ctx_on_stack.method, ctx_on_stack.route, ctx_on_stack.http_version);
        }

        if (strcmp(ctx_on_stack.method, "GET") == 0) {
            url_decode(&ctx_on_stack);
            cleanup_filepath(&ctx_on_stack);
            get_file_extension(&ctx_on_stack);
            get_mime_type(&ctx_on_stack);
            parse_headers(&ctx_on_stack);

            if (extension_is_allowed(&ctx_on_stack) && strstr(ctx_on_stack.filepath, "..") == NULL) {
                build_http_response(&ctx_on_stack);
            } else {
                build_bad_http_response(&ctx_on_stack);
            }
        } else {
            build_bad_http_response(&ctx_on_stack);
        }
    }

    if (ctx_on_stack.debug) {
        puts("Sending response");
    }

    send(client_fd, ctx_on_stack.response, strlen(ctx_on_stack.response), 0);
    close(client_fd);
    free(arg);

    return NULL;
}
```


## Parse Header

``` c
void parse_headers(ctx_t *ctx) {
    if (ctx->debug) {
        puts("parse_headers()");
    }

    char *line_end = strstr(ctx->request, "\r\n");
    
    if (line_end == NULL) {
        if (ctx->debug) puts("Invalid request");
        return;
    }

    char *current_pos = line_end;

    while (true) {
        char *header_start = current_pos + 2;
        char *header_end = strstr_with_length(header_start, "\r\n", 128); // 0x80
        
        if (header_end == NULL) break;
        
        size_t line_length = header_end - header_start;
        if (line_length == 0) break; // \r\n\r\n menandakan akhir dari headers

        // Menggunakan static buffer untuk mempermudah pembacaan
        char header_line[129]; 
        strncpy(header_line, header_start, line_length);
        header_line[line_length] = '\0';

        char *colon_pos = strchr(header_line, ':');
        
        if (colon_pos != NULL) {
            *colon_pos = '\0';
            char *header_name = header_line;
            char *header_value = colon_pos + 1;

            // Skip spasi di awal value
            while (*header_value == ' ') {
                header_value++;
            }

            size_t len = header_end - (header_start + (header_value - header_line));
            if (len > 128) len = 128;

            if (strcmp(header_name, "Host") == 0) {
                strncpy(ctx->host_header, header_value, len);
                if (ctx->debug) printf("Host: %s\n", ctx->host_header);
            } 
            else if (strcmp(header_name, "User-Agent") == 0) {
                strncpy(ctx->user_agent_header, header_value, len);
                if (ctx->debug) {
                    if (strncmp(ctx->user_agent_header, "curl", 4) == 0) {
                        printf("Curl Version: ");
                        // BUG SPOTTED: Format String Vulnerability di sini
                        printf(ctx->user_agent_header); 
                    } else {
                        printf("User-Agent: %s\n", ctx->user_agent_header);
                    }
                }
            }
            else if (strcmp(header_name, "Accept") == 0) {
                strncpy(ctx->accept_header, header_value, len);
                if (ctx->debug) printf("Accept: %s\n", ctx->accept_header);
            }
            else if (strcmp(header_name, "Accept-Language") == 0) {
                strncpy(ctx->accept_language_header, header_value, len);
                if (ctx->debug) printf("Accept-Language: %s\n", ctx->accept_language_header);
            }
            else if (strcmp(header_name, "Accept-Encoding") == 0) {
                strncpy(ctx->accept_encoding_header, header_value, len);
                if (ctx->debug) printf("Accept-Encoding: %s\n", ctx->accept_encoding_header);
            }
            else if (strcmp(header_name, "Connection") == 0) {
                strncpy(ctx->connection_header, header_value, len);
                if (ctx->debug) printf("Connection: %s\n", ctx->connection_header);
            }
        }
        current_pos = header_end;
    }
}
```

## Extension is allowed

``` c
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

bool extension_is_allowed(ctx_t *ctx) {
    if (ctx->debug) {
        puts("extension_is_allowed()");
    }

    char *allowed_extensions[] = {
        "html", "htm", "txt", "jpg", "jpeg", "png", "pdf"
    };
    
    // Secara default, hanya mengecek 2 elemen pertama ("html" dan "htm")
    size_t n = 2; 

    // Jika global variable PRIV_MODE adalah "ON", cek semua 7 ekstensi
    if (strcmp(PRIV_MODE, "ON") == 0) {
        n = 7; 
    }

    // Lakukan iterasi untuk mencocokkan ekstensi
    for (size_t i = 0; i < n; i++) {
        size_t ext_len = strlen(allowed_extensions[i]);
        
        // Membandingkan string sepanjang ekstensi yang ada di whitelist
        if (strncmp(ctx->file_extension, allowed_extensions[i], ext_len) == 0) {
            return true;
        }
    }

    return false;
}
```