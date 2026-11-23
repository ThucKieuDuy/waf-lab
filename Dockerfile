FROM php:8.0-apache
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
# Chỉ sao chép các tệp PHP mã nguồn của Web Target
COPY index.php db.php comments.php /var/www/html/
EXPOSE 80
