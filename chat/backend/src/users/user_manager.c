#include "user_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Definición de la estructura para cada nodo de usuario.
typedef struct user_node {
    char *username;
    struct user_node *next;
} user_node_t;

// Lista global de usuarios.
static user_node_t *user_list = NULL;

bool register_user(const char *username) {
    // Verificar si el usuario ya existe.
    user_node_t *current = user_list;
    while (current != NULL) {
        if (strcmp(current->username, username) == 0) {
            // El usuario ya existe.
            return false;
        }
        current = current->next;
    }
    
    // Crear un nuevo nodo para el usuario.
    user_node_t *new_node = (user_node_t *)malloc(sizeof(user_node_t));
    if (new_node == NULL) {
        return false;
    }
    
    new_node->username = strdup(username);
    if (new_node->username == NULL) {
        free(new_node);
        return false;
    }
    
    // Insertar el nuevo nodo al inicio de la lista.
    new_node->next = user_list;
    user_list = new_node;
    
    return true;
}

void remove_user(const char *username) {
    user_node_t **current = &user_list;
    while (*current != NULL) {
        if (strcmp((*current)->username, username) == 0) {
            user_node_t *to_delete = *current;
            *current = to_delete->next;
            free(to_delete->username);
            free(to_delete);
            return;
        }
        current = &((*current)->next);
    }
}

void free_all_users(void) {
    user_node_t *current = user_list;
    while (current != NULL) {
        user_node_t *next = current->next;
        free(current->username);
        free(current);
        current = next;
    }
    user_list = NULL;
}
