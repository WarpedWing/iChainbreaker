import os
import sqlite3


def isExist(filename):
    return os.path.exists(filename)


class ExporySQLiteDB:
    def __init__(self):
        self.conn = None
        self.cursor = None

    def createDB(self, filename='output.db'):
        if isExist(filename):
            return False
        self.conn = sqlite3.connect(filename)
        # Keep default text_factory (str in Py3) to get text as str
        self.cursor = self.conn.cursor()
        return True

    def createTable(self, tablename, columnlist):
        sql = 'CREATE TABLE IF NOT EXISTS ' + tablename
        sql += ' ('
        count = 0
        for column in columnlist:
            if column[1] is None or column[2] is None:
                continue
            sql += ' ' + column[1] + ' ' + column[2]  # column name
            count += 1

            if len(columnlist) > count:
                sql += ','

        sql += ' )'
        self.cursor.execute(sql)
        self.conn.commit()

    def insertRecord(self, tablename, record):
        sql = f'INSERT INTO {tablename} VALUES'
        for i in range(len(record)):
            if i == 0:
                sql += '('
            sql += ' ?'
            if (i + 1) == len(record):
                sql += ')'
            else:
                sql += ','
        self.cursor.execute(sql, record)

    def insertData(self, tablename, dataset):
        sql = ''
        sql = f'INSERT INTO {tablename}'
        sql += '('
        count = 0
        for column in dataset:
            if column[0] == 'v_Data':
                column[0] = 'data'
            sql += str(column[0])
            count += 1

            if len(dataset) > count:
                sql += ', '

        sql += ')'
        sql += ' VALUES '
        sql += '('
        count = 0
        values = []
        for data in dataset:
            if data[0] == 'cdat' or data[0] == 'mdat':
                import time

                data[1] = time.mktime(data[1].timetuple())

            if data[0] != 'data':
                try:
                    values.append(sqlite3.Binary(data[1]))
                except TypeError:
                    values.append(data[1])
            else:
                values.append(data[1])

            sql += '?'
            count += 1
            if len(dataset) > count:
                sql += ','

        sql += ')'

        try:
            self.cursor.execute(sql, values)
        except sqlite3.OperationalError:
            print(sql, values)
            self.commit()
            self.close()
            raise SystemExit(1) from None

    def commit(self):
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
