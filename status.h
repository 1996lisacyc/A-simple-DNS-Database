#ifndef __STATUS_H
#define __STATUS_H

/**
 * status code for response
 * Usage: status_str[OK], status_code[METHOD_NOT_ALLOWED] ...
 *
 * Another example for show all status code and status string
 *   for (i = 0; i < __NUM_OF_STATUS; ++i)
 *           printf("%d \"%s\"", status_code[i], status_str[i]);
 */
enum {
        OK = 0, 
        BAD_REQUEST, 
        NOT_FOUND, 
        METHOD_NOT_ALLOWED,
        __NUM_OF_STATUS,
};

const char *status_str[] = {
        "OK",
        "Bad Request",
        "Not Found",
        "Method Not Allowed",
};

const int status_code[] = {
        200, /* OK */
        400, /* Bad Request */
        404, /* Not Found */
        405, /* Method Not Allowed */
};

#endif
