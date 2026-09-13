// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Small JSON parser.
 *
 * The public functions from the original implementation are retained:
 *   skipSpaces(), readString(), readNumber(), readBool(), readValue(),
 *   readObject(), getValue()
 *
 * Additional public function:
 *   freeJsonValue()
 *
 * The parser now supports objects and arrays, JSON string escapes, strict
 * syntax checking, dynamically growing containers and complete recursive
 * cleanup on allocation/parse failures.
 */

typedef enum {
    TYPE_STRING,
    TYPE_NUMBER,
    TYPE_BOOL,
    TYPE_NULL,
    TYPE_OBJECT,
    TYPE_ARRAY
} JsonType;

struct JsonValue;

typedef struct {
    char *key;
    struct JsonValue *value;
} JsonPair;

typedef struct JsonValue {
    JsonType type;

    union {
        char *stringValue;
        double numberValue;
        int boolValue;

        struct {
            JsonPair *pairs;
            size_t count;
            size_t capacity;
        } objectValue;

        struct {
            struct JsonValue **items;
            size_t count;
            size_t capacity;
        } arrayValue;
    };
} JsonValue;

#define JSON_INITIAL_CAPACITY 8U

static void freeJsonValueInternal(JsonValue *value);

static JsonValue *parseValue(const char **text);

static JsonValue *parseObject(const char **text);

static JsonValue *parseArray(const char **text);

static char *parseString(const char **text);

static int parseNumber(const char **text, double *result);

static int parseLiteral(const char **text, const char *literal);

static int appendPair(JsonValue *object, char *key, JsonValue *value);

static int appendArrayItem(JsonValue *array, JsonValue *value);

static int growAllocation(void **ptr, size_t *capacity,
                          size_t elementSize);

static int isValueDelimiter(char c);

static char *jsonStrdup(const char *source) {
    if (source == NULL) {
        return NULL;
    }

    size_t length = strlen(source);
    if (length == SIZE_MAX) {
        return NULL;
    }

    char *copy = malloc(length + 1U);
    if (copy != NULL) {
        memcpy(copy, source, length + 1U);
    }
    return copy;
}

static int growAllocation(void **ptr, size_t *capacity, size_t elementSize) {
    if (ptr == NULL || capacity == NULL || elementSize == 0U) {
        return 0;
    }

    size_t oldCapacity = *capacity;
    size_t newCapacity = oldCapacity == 0U ? JSON_INITIAL_CAPACITY : oldCapacity;

    if (oldCapacity != 0U) {
        if (oldCapacity > SIZE_MAX / 2U) {
            return 0;
        }
        newCapacity = oldCapacity * 2U;
    }

    if (newCapacity > SIZE_MAX / elementSize) {
        return 0;
    }

    void *newMemory = realloc(*ptr, newCapacity * elementSize);
    if (newMemory == NULL) {
        return 0;
    }

    *ptr = newMemory;
    *capacity = newCapacity;
    return 1;
}

void skipSpaces(const char **text) {
    if (text == NULL || *text == NULL) {
        return;
    }

    while (isspace((unsigned char) **text)) {
        (*text)++;
    }
}

static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int appendChar(char **buffer, size_t *length, size_t *capacity, char c) {
    if (*length + 1U >= *capacity) {
        size_t newCapacity = *capacity == 0U ? 32U : *capacity * 2U;
        if (newCapacity < *capacity || newCapacity > SIZE_MAX / 2U) {
            return 0;
        }

        char *newBuffer = realloc(*buffer, newCapacity);
        if (newBuffer == NULL) {
            return 0;
        }

        *buffer = newBuffer;
        *capacity = newCapacity;
    }

    (*buffer)[(*length)++] = c;
    return 1;
}

static int appendUtf8(char **buffer, size_t *length, size_t *capacity,
                      unsigned int codepoint) {
    if (codepoint <= 0x7FU) {
        return appendChar(buffer, length, capacity, (char) codepoint);
    }
    if (codepoint <= 0x7FFU) {
        return appendChar(buffer, length, capacity, (char) (0xC0U | (codepoint >> 6))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | (codepoint & 0x3FU)));
    }
    if (codepoint <= 0xFFFFU) {
        return appendChar(buffer, length, capacity, (char) (0xE0U | (codepoint >> 12))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | ((codepoint >> 6) & 0x3FU))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | (codepoint & 0x3FU)));
    }
    if (codepoint <= 0x10FFFFU) {
        return appendChar(buffer, length, capacity, (char) (0xF0U | (codepoint >> 18))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | ((codepoint >> 12) & 0x3FU))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | ((codepoint >> 6) & 0x3FU))) &&
               appendChar(buffer, length, capacity, (char) (0x80U | (codepoint & 0x3FU)));
    }
    return 0;
}

static int parseHex4(const char **text, unsigned int *value) {
    unsigned int result = 0U;

    for (int i = 0; i < 4; ++i) {
        int hex = hexValue((*text)[i]);
        if (hex < 0) {
            return 0;
        }
        result = (result << 4) | (unsigned int) hex;
    }

    *text += 4;
    *value = result;
    return 1;
}

static char *parseString(const char **text) {
    if (text == NULL || *text == NULL || **text != '"') {
        return NULL;
    }

    (*text)++;

    char *result = NULL;
    size_t length = 0U;
    size_t capacity = 0U;

    while (**text != '\0' && **text != '"') {
        unsigned char c = (unsigned char) **text;

        if (c < 0x20U) {
            free(result);
            return NULL;
        }

        if (c != '\\') {
            if (!appendChar(&result, &length, &capacity, (char) c)) {
                free(result);
                return NULL;
            }
            (*text)++;
            continue;
        }

        (*text)++;
        switch (**text) {
            case '"':
            case '\\':
            case '/':
                if (!appendChar(&result, &length, &capacity, **text)) {
                    free(result);
                    return NULL;
                }
                (*text)++;
                break;

            case 'b':
                if (!appendChar(&result, &length, &capacity, '\b')) goto string_error;
                (*text)++;
                break;
            case 'f':
                if (!appendChar(&result, &length, &capacity, '\f')) goto string_error;
                (*text)++;
                break;
            case 'n':
                if (!appendChar(&result, &length, &capacity, '\n')) goto string_error;
                (*text)++;
                break;
            case 'r':
                if (!appendChar(&result, &length, &capacity, '\r')) goto string_error;
                (*text)++;
                break;
            case 't':
                if (!appendChar(&result, &length, &capacity, '\t')) goto string_error;
                (*text)++;
                break;

            case 'u': {
                unsigned int codepoint;
                (*text)++;
                if (!parseHex4(text, &codepoint)) goto string_error;

                /* Handle UTF-16 surrogate pairs. */
                if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
                    const char *saved = *text;
                    if (saved[0] == '\\' && saved[1] == 'u') {
                        unsigned int low;
                        *text += 2;
                        if (!parseHex4(text, &low) || low < 0xDC00U || low > 0xDFFFU) {
                            goto string_error;
                        }
                        codepoint = 0x10000U +
                                    ((codepoint - 0xD800U) << 10) +
                                    (low - 0xDC00U);
                    } else {
                        goto string_error;
                    }
                } else if (codepoint >= 0xDC00U && codepoint <= 0xDFFFU) {
                    goto string_error;
                }

                if (!appendUtf8(&result, &length, &capacity, codepoint)) {
                    goto string_error;
                }
                break;
            }

            default:
                goto string_error;
        }
    }

    if (**text != '"') {
        free(result);
        return NULL;
    }
    (*text)++;

    if (!appendChar(&result, &length, &capacity, '\0')) {
        free(result);
        return NULL;
    }

    return result;

string_error:
    free(result);
    return NULL;
}

/* Read a JSON string. Caller owns the returned memory. */
char *readString(const char **text) {
    return parseString(text);
}

static int parseNumber(const char **text, double *result) {
    if (text == NULL || *text == NULL || result == NULL) {
        return 0;
    }

    errno = 0;
    char *end = NULL;
    double value = strtod(*text, &end);

    if (end == *text || errno == ERANGE) {
        return 0;
    }

    if (!isValueDelimiter(*end)) {
        return 0;
    }

    *text = end;
    *result = value;
    return 1;
}

/* Read a JSON number. Invalid input returns 0 and leaves the pointer unchanged. */
double readNumber(const char **text) {
    double result = 0.0;
    (void) parseNumber(text, &result);
    return result;
}

static int parseLiteral(const char **text, const char *literal) {
    size_t length = strlen(literal);

    if (strncmp(*text, literal, length) != 0 ||
        !isValueDelimiter((*text)[length])) {
        return 0;
    }

    *text += length;
    return 1;
}

/* Read true/false. Kept for compatibility with the original API. */
int readBool(const char **text) {
    if (text == NULL || *text == NULL) {
        return 0;
    }

    if (parseLiteral(text, "true")) {
        return 1;
    }
    if (parseLiteral(text, "false")) {
        return 0;
    }
    return 0;
}

static int isValueDelimiter(char c) {
    return c == '\0' || c == ',' || c == ']' || c == '}' ||
           isspace((unsigned char) c);
}

static JsonValue *newJsonValue(JsonType type) {
    JsonValue *value = calloc(1U, sizeof(*value));
    if (value != NULL) {
        value->type = type;
    }
    return value;
}

static int appendPair(JsonValue *object, char *key, JsonValue *value) {
    if (object == NULL || object->type != TYPE_OBJECT || key == NULL || value == NULL) {
        return 0;
    }

    if (object->objectValue.count == object->objectValue.capacity &&
        !growAllocation((void **) &object->objectValue.pairs,
                        &object->objectValue.capacity,
                        sizeof(*object->objectValue.pairs))) {
        return 0;
    }

    object->objectValue.pairs[object->objectValue.count].key = key;
    object->objectValue.pairs[object->objectValue.count].value = value;
    object->objectValue.count++;
    return 1;
}

static int appendArrayItem(JsonValue *array, JsonValue *value) {
    if (array == NULL || array->type != TYPE_ARRAY || value == NULL) {
        return 0;
    }

    if (array->arrayValue.count == array->arrayValue.capacity &&
        !growAllocation((void **) &array->arrayValue.items,
                        &array->arrayValue.capacity,
                        sizeof(*array->arrayValue.items))) {
        return 0;
    }

    array->arrayValue.items[array->arrayValue.count++] = value;
    return 1;
}

static JsonValue *parseObject(const char **text) {
    if (text == NULL || *text == NULL || **text != '{') {
        return NULL;
    }

    JsonValue *object = newJsonValue(TYPE_OBJECT);
    if (object == NULL) {
        return NULL;
    }

    (*text)++;
    skipSpaces(text);

    if (**text == '}') {
        (*text)++;
        return object;
    }

    for (;;) {
        skipSpaces(text);
        char *key = parseString(text);
        if (key == NULL) {
            freeJsonValueInternal(object);
            return NULL;
        }

        skipSpaces(text);
        if (**text != ':') {
            free(key);
            freeJsonValueInternal(object);
            return NULL;
        }
        (*text)++;

        skipSpaces(text);
        JsonValue *value = parseValue(text);
        if (value == NULL) {
            free(key);
            freeJsonValueInternal(object);
            return NULL;
        }

        if (!appendPair(object, key, value)) {
            free(key);
            freeJsonValueInternal(value);
            freeJsonValueInternal(object);
            return NULL;
        }

        skipSpaces(text);
        if (**text == '}') {
            (*text)++;
            return object;
        }

        if (**text != ',') {
            freeJsonValueInternal(object);
            return NULL;
        }
        (*text)++;
        skipSpaces(text);

        /* Trailing commas are not valid JSON. */
        if (**text == '}') {
            freeJsonValueInternal(object);
            return NULL;
        }
    }
}

static JsonValue *parseArray(const char **text) {
    if (text == NULL || *text == NULL || **text != '[') {
        return NULL;
    }

    JsonValue *array = newJsonValue(TYPE_ARRAY);
    if (array == NULL) {
        return NULL;
    }

    (*text)++;
    skipSpaces(text);

    if (**text == ']') {
        (*text)++;
        return array;
    }

    for (;;) {
        skipSpaces(text);
        JsonValue *value = parseValue(text);
        if (value == NULL) {
            freeJsonValueInternal(array);
            return NULL;
        }

        if (!appendArrayItem(array, value)) {
            freeJsonValueInternal(value);
            freeJsonValueInternal(array);
            return NULL;
        }

        skipSpaces(text);
        if (**text == ']') {
            (*text)++;
            return array;
        }

        if (**text != ',') {
            freeJsonValueInternal(array);
            return NULL;
        }
        (*text)++;
        skipSpaces(text);

        /* Trailing commas are not valid JSON. */
        if (**text == ']') {
            freeJsonValueInternal(array);
            return NULL;
        }
    }
}

static JsonValue *parseValue(const char **text) {
    if (text == NULL || *text == NULL) {
        return NULL;
    }

    skipSpaces(text);

    switch (**text) {
        case '"': {
            char *string = parseString(text);
            if (string == NULL) return NULL;

            JsonValue *value = newJsonValue(TYPE_STRING);
            if (value == NULL) {
                free(string);
                return NULL;
            }
            value->stringValue = string;
            return value;
        }

        case '{':
            return parseObject(text);

        case '[':
            return parseArray(text);

        case 't':
            if (parseLiteral(text, "true")) {
                JsonValue *value = newJsonValue(TYPE_BOOL);
                if (value != NULL) value->boolValue = 1;
                return value;
            }
            return NULL;

        case 'f':
            if (parseLiteral(text, "false")) {
                JsonValue *value = newJsonValue(TYPE_BOOL);
                if (value != NULL) value->boolValue = 0;
                return value;
            }
            return NULL;

        case 'n':
            if (parseLiteral(text, "null")) {
                return newJsonValue(TYPE_NULL);
            }
            return NULL;

        default:
            if (**text == '-' || isdigit((unsigned char) **text)) {
                double number;
                if (!parseNumber(text, &number)) return NULL;

                JsonValue *value = newJsonValue(TYPE_NUMBER);
                if (value != NULL) value->numberValue = number;
                return value;
            }
            return NULL;
    }
}

/* Read an object. Caller owns the returned JSON tree. */
JsonValue *readObject(const char **text) {
    return parseObject(text);
}

/* Read any JSON value. Caller owns the returned JSON tree. */
JsonValue *readValue(const char **text) {
    return parseValue(text);
}

static void freeJsonValueInternal(JsonValue *value) {
    if (value == NULL) {
        return;
    }

    switch (value->type) {
        case TYPE_STRING:
            free(value->stringValue);
            break;

        case TYPE_OBJECT:
            for (size_t i = 0; i < value->objectValue.count; ++i) {
                free(value->objectValue.pairs[i].key);
                freeJsonValueInternal(value->objectValue.pairs[i].value);
            }
            free(value->objectValue.pairs);
            break;

        case TYPE_ARRAY:
            for (size_t i = 0; i < value->arrayValue.count; ++i) {
                freeJsonValueInternal(value->arrayValue.items[i]);
            }
            free(value->arrayValue.items);
            break;

        case TYPE_NUMBER:
        case TYPE_BOOL:
        case TYPE_NULL:
            break;
    }

    free(value);
}

/* Free a complete JSON tree. Safe to call with NULL. */
void freeJsonValue(JsonValue *value) {
    freeJsonValueInternal(value);
}

static JsonValue *findObjectValue(JsonValue *object, const char *key) {
    if (object == NULL || object->type != TYPE_OBJECT || key == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < object->objectValue.count; ++i) {
        if (strcmp(object->objectValue.pairs[i].key, key) == 0) {
            return object->objectValue.pairs[i].value;
        }
    }

    return NULL;
}

/*
 * Get a value by a dotted object path, e.g. "details.name".
 *
 * Array indexes are also supported using numeric path components, e.g.
 * "users.0.name".
 *
 * The returned pointer belongs to root and must not be freed separately.
 */
JsonValue *getValue(JsonValue *root, const char *path) {
    if (root == NULL || path == NULL || *path == '\0') {
        return root;
    }

    char *pathCopy = jsonStrdup(path);
    if (pathCopy == NULL) {
        return NULL;
    }

    JsonValue *current = root;
    char *token = strtok(pathCopy, ".");

    while (token != NULL) {
        if (current == NULL) {
            free(pathCopy);
            return NULL;
        }

        if (current->type == TYPE_OBJECT) {
            current = findObjectValue(current, token);
        } else if (current->type == TYPE_ARRAY) {
            char *end = NULL;
            errno = 0;
            unsigned long long index = strtoull(token, &end, 10);

            if (errno == ERANGE || end == token || *end != '\0' ||
                index > (unsigned long long) SIZE_MAX ||
                (size_t) index >= current->arrayValue.count) {
                free(pathCopy);
                return NULL;
            }

            current = current->arrayValue.items[(size_t) index];
        } else {
            free(pathCopy);
            return NULL;
        }

        token = strtok(NULL, ".");
    }

    free(pathCopy);
    return current;
}

/*
 * Optional convenience function for callers that want to ensure that the
 * complete input consists of exactly one JSON value.
 *
 * Returns NULL on syntax error, allocation failure or trailing data.
 */
JsonValue *parseJson(const char *text) {
    if (text == NULL) {
        return NULL;
    }

    const char *cursor = text;
    JsonValue *root = readValue(&cursor);
    if (root == NULL) {
        return NULL;
    }

    skipSpaces(&cursor);
    if (*cursor != '\0') {
        freeJsonValue(root);
        return NULL;
    }

    return root;
}
