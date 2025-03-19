#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "config.h"
#include "utils/logger.h"
#include "users/user_manager.h"
#include <cjson/cJSON.h>  // Asegúrate de tener cJSON instalada

static int callback_chat(struct lws *wsi,
                         enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
    switch (reason)
    {
        case LWS_CALLBACK_ESTABLISHED:
            log_info("Nuevo cliente conectado");
            break;

        case LWS_CALLBACK_RECEIVE:
        {
            char *raw_msg = (char *)in;
            log_info("Mensaje recibido: %s", raw_msg);

            // Extraer la parte que corresponde al JSON
            char *start = strchr(raw_msg, '{');
            char *end = strrchr(raw_msg, '}');
            if (!start || !end || end < start) {
                log_error("Mensaje recibido no contiene un JSON válido");
                break;
            }
            size_t json_len = end - start + 1;
            char *json_str = malloc(json_len + 1);
            if (!json_str) {
                log_error("Error de memoria al asignar json_str");
                break;
            }
            strncpy(json_str, start, json_len);
            json_str[json_len] = '\0';

            log_info("Procesando JSON: %s", json_str);

            // Parsear el JSON usando cJSON
            cJSON *json = cJSON_Parse(json_str);
            free(json_str);
            if (json == NULL) {
                log_error("Error al parsear JSON");
                break;
            }

            // Procesar el mensaje según su "type"
            cJSON *type = cJSON_GetObjectItemCaseSensitive(json, "type");
            if (cJSON_IsString(type) && type->valuestring != NULL) {
                if (strcmp(type->valuestring, "register") == 0) {
                    cJSON *sender = cJSON_GetObjectItemCaseSensitive(json, "sender");
                    if (cJSON_IsString(sender) && sender->valuestring != NULL) {
                        bool result = register_user(sender->valuestring);
                        if (result) {
                            log_info("Usuario %s registrado exitosamente", sender->valuestring);
                            
                            // Preparar respuesta de registro exitoso
                            cJSON *response = cJSON_CreateObject();
                            cJSON_AddStringToObject(response, "type", "register_success");
                            cJSON_AddStringToObject(response, "sender", "server");
                            cJSON_AddStringToObject(response, "content", "Registro exitoso");
                            
                            char *response_str = cJSON_PrintUnformatted(response);
                            size_t response_len = strlen(response_str);
                            unsigned char buf[LWS_PRE + response_len];
                            memcpy(&buf[LWS_PRE], response_str, response_len);
                            lws_write(wsi, &buf[LWS_PRE], response_len, LWS_WRITE_TEXT);
                            
                            cJSON_Delete(response);
                            free(response_str);
                        } else {
                            log_error("El usuario %s ya existe", sender->valuestring);
                            
                            // Preparar respuesta de error
                            cJSON *response = cJSON_CreateObject();
                            cJSON_AddStringToObject(response, "type", "error");
                            cJSON_AddStringToObject(response, "sender", "server");
                            cJSON_AddStringToObject(response, "content", "El usuario ya existe");
                            
                            char *response_str = cJSON_PrintUnformatted(response);
                            size_t response_len = strlen(response_str);
                            unsigned char buf[LWS_PRE + response_len];
                            memcpy(&buf[LWS_PRE], response_str, response_len);
                            lws_write(wsi, &buf[LWS_PRE], response_len, LWS_WRITE_TEXT);
                            
                            cJSON_Delete(response);
                            free(response_str);
                        }
                    }
                }
            }
            cJSON_Delete(json);
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE:
            // Se pueden enviar mensajes pendientes aquí si es necesario.
            break;

        case LWS_CALLBACK_CLOSED:
            log_info("Cliente desconectado");
            // Aquí podrías remover al usuario de la lista, si fuera necesario.
            break;

        default:
            break;
    }
    return 0;
}

// Definición de los protocolos
static struct lws_protocols protocols[] = {
    {
        "chat-protocol",
        callback_chat,
        0,
        1024,
    },
    { NULL, NULL, 0, 0 }
};

int main(void)
{
    struct lws_context_creation_info info;
    struct lws_context *context;

    memset(&info, 0, sizeof(info));
    info.port = SERVER_PORT;
    info.protocols = protocols;

    context = lws_create_context(&info);
    if (context == NULL) {
        log_error("Error al iniciar libwebsockets");
        return -1;
    }
    log_info("Servidor iniciado en el puerto %d", SERVER_PORT);

    while (1) {
        lws_service(context, 50);
    }
    lws_context_destroy(context);
    return 0;
}
