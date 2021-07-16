#!/usr/bin/env python3

import os
import sys
import psycopg2
import hashlib

def io_md5(target):
    blocksize = 65536
    hasher = hashlib.md5()

    with open(target, 'rb') as ifp:
        buf = ifp.read(blocksize)
        while buf:
            hasher.update(buf)
            buf = ifp.read(blocksize)
        return hasher.hexdigest()

def query_(query, psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        cur = dbh.cursor()
        cur.execute(query)
        return cur.fetchone()

    except:
        return None

def get_iid(infile, psql_ip):
    md5 = io_md5(infile)
    q = "SELECT id FROM image WHERE hash = '%s'" % md5
    image_id = query_(q, psql_ip)

    if image_id:
        return image_id[0]
    else:
        return ""

def get_brand(infile, psql_ip):
    md5 = io_md5(infile)
    q = "SELECT brand_id FROM image WHERE hash = '%s'" % md5
    brand_id = query_(q, psql_ip)

    if brand_id:
        q = "SELECT name FROM brand WHERE id = '%s'" % brand_id
        brand = query_(q, psql_ip)
        if brand:
            return brand[0]
        else:
            return ""
    else:
        return ""

def db_select(column,iid):
    if os.getenv('FIRMAE_DOCKER') == 'true':
        psql_ip = "172.17.0.1"
    else:
        psql_ip = "127.0.0.1"

    dbh = get_db(psql_ip)
    if dbh:
        cur = dbh.cursor()
        cur.execute("select {} from image where id={};".format(column,iid))
        rows = cur.fetchall()
        print(rows[0][0])
        dbh.close()
    else:
        print("fail")
        dbh.close()
        exit

def db_update(column,value,iid):
    if os.getenv('FIRMAE_DOCKER') == 'true':
        psql_ip = "172.17.0.1"
    else:
        psql_ip = "127.0.0.1"

    dbh = get_db(psql_ip)
    if dbh:
        cur = dbh.cursor()
        cur.execute("update image set {}=%s where id=%s;".format(column),(value,iid))
        if cur.rowcount == 1:
            dbh.commit()
        dbh.close()
    else:
        print("fail")
        dbh.close()
        exit

def check_connection(psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        dbh.close()
        return 0
    except:
        return 1

def get_db(psql_ip):
    try:
        dbh = psycopg2.connect(database="firmware",
                               user="firmadyne",
                               password="firmadyne",
                               host=psql_ip)
        return dbh
    except:
        return 1

# command line
if __name__ == '__main__':
    [infile, psql_ip] = sys.argv[2:4]
    if sys.argv[1] == 'get_iid':
        print(get_iid(infile, psql_ip))
    if sys.argv[1] == 'get_brand':
        print(get_brand(infile, psql_ip))
    if sys.argv[1] == 'check_connection':
        exit(check_connection(psql_ip))
    if sys.argv[1] == 'select':
        db_select(sys.argv[2],sys.argv[3])
    if sys.argv[1] == 'update':
        db_update(sys.argv[2],sys.argv[3],sys.argv[4])
