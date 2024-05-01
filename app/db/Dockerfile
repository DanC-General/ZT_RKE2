FROM mysql:8

ENV MYSQL_ROOT_PASSWORD=password123!.

COPY db_init.sql /docker-entrypiont-initdb.d

VOLUME /var/lib/mysql

# EXPOSE 3306