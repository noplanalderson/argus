FROM php:8.3-fpm

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    cron \
    libcurl4-openssl-dev \
    wget \
    && docker-php-ext-install mysqli pdo_mysql curl dba sockets \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Set working directory
WORKDIR /var/www/html

# Copy application code
COPY ./argus /var/www/html

# Install PHP dependencies
RUN composer install --no-dev --optimize-autoloader

# Set up cron
RUN if [ -f "/var/www/html/cron/blocklist-cron" ]; then \
        cp /var/www/html/script/blocklist-cron /etc/cron.d/blocklist-cron && \
        chmod 0644 /etc/cron.d/blocklist-cron && \
        crontab /etc/cron.d/blocklist-cron; \
    fi

# Create log files
RUN touch /var/log/ip-blocklist.log && chmod 666 /var/log/ip-blocklist.log

# Generate blocklist if not exist
RUN if [ ! -f "/var/www/html/blocklist/argus-ipsets.cdb" ]; then \
        RUN /bin/bash /var/www/html/script/argus-blocklist.sh; \
    fi

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

CMD cron && php-fpm