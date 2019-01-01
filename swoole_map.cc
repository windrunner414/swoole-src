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
#include "SharedHashFile.hpp"

static zend_class_entry swoole_map_ce;
static zend_class_entry *swoole_map_ce_ptr;
static zend_object_handlers swoole_map_handlers;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_map_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_map_construct, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_map_set, 0, 0, 2)
    ZEND_ARG_INFO(0, key)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_map_get, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_map_del, 0, 0, 1)
    ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

static PHP_METHOD(swoole_map, __construct);
static PHP_METHOD(swoole_map, __destruct);
static PHP_METHOD(swoole_map, set);
static PHP_METHOD(swoole_map, get);
static PHP_METHOD(swoole_map, del);

static const zend_function_entry swoole_map_methods[] =
{
    PHP_ME(swoole_map, __construct, arginfo_swoole_map_construct, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_map, __destruct,  arginfo_swoole_map_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_map, set,         arginfo_swoole_map_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_map, get,         arginfo_swoole_map_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_map, del,         arginfo_swoole_map_del, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_map_init(int module_number)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_map, "Swoole\\Map", "swoole_map", NULL, swoole_map_methods);
    SWOOLE_SET_CLASS_SERIALIZABLE(swoole_map, zend_class_serialize_deny, zend_class_unserialize_deny);
    SWOOLE_SET_CLASS_CLONEABLE(swoole_map, zend_class_clone_deny);
    SWOOLE_SET_CLASS_UNSET_PROPERTY_HANDLER(swoole_map, zend_class_unset_property_deny);
}

PHP_METHOD(swoole_map, __construct)
{
    char *path;
    size_t pathlen;
    char *file;
    size_t filelen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &path, &pathlen, &file, &filelen) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto map = new SharedHashFile;
    if (!map->Attach(path, file, 0))
    {
        delete map;
        zend_throw_exception(swoole_exception_ce_ptr, "swoole_map open failed.", SW_ERROR_MALLOC_FAIL);
        RETURN_FALSE;
    }

    swoole_set_object(getThis(), map);
}

static PHP_METHOD(swoole_map, set)
{
    char *key;
    size_t keylen;
    char *val;
    size_t vallen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &key, &keylen, &val, &vallen) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto map = (SharedHashFile *) swoole_get_object(getThis());
    map->MakeHash(key, keylen);
    if (map->PutKeyVal(val, vallen) != SHF_UID_NONE)
    {
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_map, get)
{
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto map = (SharedHashFile *) swoole_get_object(getThis());
    map->MakeHash(key, keylen);
    if (!map->GetKeyValCopy())
    {
        RETURN_FALSE;
    }

    RETURN_STRINGL(shf_val, shf_val_len);
}

static PHP_METHOD(swoole_map, del)
{
    char *key;
    size_t keylen;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &key, &keylen) == FAILURE)
    {
        RETURN_FALSE;
    }

    auto map = (SharedHashFile *) swoole_get_object(getThis());
    map->MakeHash(key, keylen);
    if (map->DelKeyVal())
    {
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_map, __destruct)
{
    auto map = (SharedHashFile *) swoole_get_object(getThis());
    delete map;
    swoole_set_object(getThis(), NULL);
}
