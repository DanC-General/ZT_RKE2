FROM mysql:8

ENV MYSQL_ROOT_PASSWORD=password123!.

COPY db_init.sql /docker-entrypoint-initdb.d

# VOLUME /var/lib/mysql

# EXPOSE 3306