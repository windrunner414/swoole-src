/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"

static PHP_METHOD(swoole_buffer, __construct);
static PHP_METHOD(swoole_buffer, __destruct);
static PHP_METHOD(swoole_buffer, __toString);
static PHP_METHOD(swoole_buffer, setEndian);
static PHP_METHOD(swoole_buffer, append);
static PHP_METHOD(swoole_buffer, substr);
static PHP_METHOD(swoole_buffer, read);
static PHP_METHOD(swoole_buffer, readInt8);
static PHP_METHOD(swoole_buffer, write);
static PHP_METHOD(swoole_buffer, writeInt8);
static PHP_METHOD(swoole_buffer, expand);
static PHP_METHOD(swoole_buffer, recycle);
static PHP_METHOD(swoole_buffer, clear);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_construct, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_setEndian, 0, 0, 0)
    ZEND_ARG_INFO(0, endian)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_expand, 0, 0, 1)
    ZEND_ARG_INFO(0, size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_substr, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
    ZEND_ARG_INFO(0, seek)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_write, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_writeInt8, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_read, 0, 0, 2)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_readInt8, 0, 0, 1)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_buffer_append, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_buffer_methods[] =
{
    PHP_ME(swoole_buffer, __construct, arginfo_swoole_buffer_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, __destruct, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, __toString, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, setEndian, arginfo_swoole_buffer_setEndian, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, substr, arginfo_swoole_buffer_substr, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, write, arginfo_swoole_buffer_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, writeInt8, arginfo_swoole_buffer_writeInt8, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, read, arginfo_swoole_buffer_read, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, readInt8, arginfo_swoole_buffer_readInt8, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, append, arginfo_swoole_buffer_append, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, expand, arginfo_swoole_buffer_expand, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, recycle, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_buffer, clear, arginfo_swoole_buffer_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static zend_class_entry swoole_buffer_ce;
zend_class_entry *swoole_buffer_ce_ptr;
static zend_object_handlers swoole_buffer_handlers;

void swoole_buffer_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_buffer, "Swoole\\Buffer", "swoole_buffer", NULL, swoole_buffer_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_buffer, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_buffer, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_buffer, zend_class_unset_property_deny);
}

static void swoole_buffer_recycle(swString *buffer)
{
    if (buffer->offset == 0)
    {
        return;
    }

    long length;
    length = buffer->length - buffer->offset;
    if (length > 0)
    {
        memmove(buffer->str, buffer->str + buffer->offset, length);
    }

    buffer->offset = 0;
    buffer->length = length;
}

static size_t swoole_buffer_write(swString *buffer, swString *str, size_t offset)
{
    if (str->length < 1)
    {
        php_error_docref(NULL, E_WARNING, "string to write is empty.");
        return -1;
    }

    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }
    if (offset < 0)
    {
        php_error_docref(NULL, E_WARNING, "offset(%ld) is out of bounds.", offset);
        return -1;
    }

    offset += buffer->offset;

    if ((str->length + offset) > buffer->size && (str->length + offset) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL, E_WARNING, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        return -1;
    }

    if (swString_write(buffer, offset, str) == SW_OK)
    {
        return (buffer->length - buffer->offset);
    }
    else
    {
        return -1;
    }
}

static char *swoole_buffer_read(swString *buffer, size_t offset, size_t length)
{
    if (offset < 0)
    {
        offset = buffer->length - buffer->offset + offset;
    }

    if (offset < 0)
    {
        php_error_docref(NULL, E_WARNING, "offset(%ld) is out of bounds.", offset);
        return NULL;
    }

    offset += buffer->offset;

    if (length > buffer->length - offset)
    {
        return NULL;
    }

    return (buffer->str + offset);
}

static void swoole_buffer_to_endian(void *i, uint8_t size, uint8_t endian)
{
    if (endian == SW_HOST_ENDIAN || endian == swoole_get_host_endian())
    {
        return;
    }

    switch (size)
    {
    case 16:
        *(uint16_t *)i = swoole_swap_endian16(*(uint16_t *)i);
        break;
    case 32:
        *(uint32_t *)i = swoole_swap_endian32(*(uint32_t *)i);
        break;
    case 64:
        *(uint64_t *)i = swoole_swap_endian64(*(uint64_t *)i);
        break;
    default:
        break;
    }
}

static PHP_METHOD(swoole_buffer, __construct)
{
    long size = SW_STRING_BUFFER_DEFAULT;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (size < 1)
    {
        zend_throw_exception(swoole_exception_ce_ptr, "buffer size can't be less than 0.", SW_ERROR_INVALID_PARAMS);
        RETURN_FALSE;
    }
    else if (size > SW_STRING_BUFFER_MAXLEN)
    {
        zend_throw_exception_ex(swoole_exception_ce_ptr, errno, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    swString *buffer = swString_new(size);
    if (buffer == NULL)
    {
        zend_throw_exception_ex(swoole_exception_ce_ptr, errno, "malloc(%ld) failed.", size);
        RETURN_FALSE;
    }

    swoole_set_object(getThis(), buffer);
    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("capacity"), size);
    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"), 0);
    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("endian"), SW_HOST_ENDIAN);
}

static PHP_METHOD(swoole_buffer, __destruct)
{
    SW_PREVENT_USER_DESTRUCT;

    swString *buffer = swoole_get_object(getThis());
    if (buffer)
    {
        swString_free(buffer);
    }
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_buffer, setEndian)
{
    long endian = SW_HOST_ENDIAN;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &endian) == FAILURE)
    {
        RETURN_FALSE;
    }

    if (endian < SW_HOST_ENDIAN || endian > SW_LITTLE_ENDIAN)
    {
        endian = SW_HOST_ENDIAN;
    }

    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("endian"), endian);
}

static PHP_METHOD(swoole_buffer, append)
{
    swString str;
    bzero(&str, sizeof(str));

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }
    if (str.length < 1)
    {
        php_error_docref(NULL, E_WARNING, "string empty.");
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());

    if ((str.length + buffer->length) > buffer->size && (str.length + buffer->length) > SW_STRING_BUFFER_MAXLEN)
    {
        php_error_docref(NULL, E_WARNING, "buffer size can't exceed %d", SW_STRING_BUFFER_MAXLEN);
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    if (swString_append(buffer, &str) == SW_OK)
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("capacity"), buffer->size);
        }
        zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"),
                buffer->length - buffer->offset);
        RETURN_LONG(buffer->length - buffer->offset);
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, substr)
{
    long offset;
    long length = -1;
    zend_bool remove = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|lb", &offset, &length, &remove) == FAILURE)
    {
        RETURN_FALSE;
    }
    swString *buffer = swoole_get_object(getThis());

    if (remove && !(offset == 0 && length <= buffer->length))
    {
        remove = 0;
    }
    if (offset < 0)
    {
        offset = buffer->length + offset;
    }
    offset += buffer->offset;
    if (length < 0)
    {
        length = buffer->length - offset;
    }
    if (offset + length > buffer->length)
    {
        swoole_php_error(E_WARNING, "offset(%ld, %ld) is out of bounds.", offset, length);
        RETURN_FALSE;
    }
    if (remove)
    {
        buffer->offset += length;
        zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"), buffer->length - buffer->offset);

        if (buffer->offset > SW_STRING_BUFFER_GARBAGE_MIN && buffer->offset * SW_STRING_BUFFER_GARBAGE_RATIO > buffer->size)
        {
            swoole_buffer_recycle(buffer);
        }
    }
    RETURN_STRINGL(buffer->str + offset, length);
}

static PHP_METHOD(swoole_buffer, __toString)
{
    swString *buffer = swoole_get_object(getThis());
    RETURN_STRINGL(buffer->str + buffer->offset, buffer->length - buffer->offset);
}

static PHP_METHOD(swoole_buffer, write)
{
    long offset;
    swString str;
    swString *buffer = swoole_get_object(getThis());

    bzero(&str, sizeof(str));

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ls", &offset, &str.str, &str.length) == FAILURE)
    {
        RETURN_FALSE;
    }

    size_t size_old = buffer->size;
    size_t retval = swoole_buffer_write(swoole_get_object(getThis()), &str, offset);
    if (retval < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("capacity"), buffer->size);
        }
        zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"),
        buffer->length - buffer->offset);

        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_buffer, writeInt8)
{
    long offset;
    long i;
    int8_t data;
    swString str;
    swString *buffer = swoole_get_object(getThis());

    bzero(&str, sizeof(str));

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &offset, &i) == FAILURE)
    {
        RETURN_FALSE;
    }

    data = (int8_t)i;

    str.str = (char *)&data;
    str.length = sizeof(data);

    size_t size_old = buffer->size;
    size_t retval = swoole_buffer_write(buffer, &str, offset);
    if (retval < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        if (buffer->size > size_old)
        {
            zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("capacity"), buffer->size);
        }
        zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"),
        buffer->length - buffer->offset);

        RETURN_LONG(retval);
    }
}

static PHP_METHOD(swoole_buffer, read)
{
    long offset;
    long length;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ll", &offset, &length) == FAILURE)
    {
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    char *retval = swoole_buffer_read(buffer, offset, length);
    if (retval == NULL)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_STRINGL(retval, length);
    }
}

static PHP_METHOD(swoole_buffer, readInt8)
{
    long offset;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &offset) == FAILURE)
    {
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    int8_t *retval = (int8_t *)swoole_buffer_read(buffer, offset, sizeof(int8_t));
    if (retval == NULL)
    {
        RETURN_FALSE;
    }
    else
    {
        RETURN_LONG(*retval);
    }
}

static PHP_METHOD(swoole_buffer, expand)
{
    long size = -1;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &size) == FAILURE)
    {
        RETURN_FALSE;
    }

    swString *buffer = swoole_get_object(getThis());

    if (size <= buffer->size)
    {
        php_error_docref(NULL, E_WARNING, "new size must be more than %ld", buffer->size);
        RETURN_FALSE;
    }

    if (swString_extend(buffer, size) == SW_OK)
    {
        zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("capacity"), size);
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_buffer, recycle)
{
    swString *buffer = swoole_get_object(getThis());

    swoole_buffer_recycle(buffer);

    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"), buffer->length);
}

static PHP_METHOD(swoole_buffer, clear)
{
    swString *buffer = swoole_get_object(getThis());
    buffer->length = 0;
    buffer->offset = 0;
    zend_update_property_long(swoole_buffer_ce_ptr, getThis(), ZEND_STRL("length"), 0);
}
