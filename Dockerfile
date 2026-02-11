FROM php:8.3-fpm

# Install dependencies
FROM php:8.2-fpm

RUN apt-get update && apt-get install -y \
    git \
    unzip \
    cron \
    libcurl4-openssl-dev \
    libxml2-dev \
    wget \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    zlib1g-dev \
    libzip-dev \
    libonig-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install \
    mysqli \
    gd \
    bcmath \
    xml \
    dom \
    mbstring \
    pdo_mysql \
    curl \
    dba \
    sockets \
    zip \
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
RUN touch /var/log/argus_tip.log && chmod 666 /var/log/argus_tip.log

# Generate blocklist if not exist
RUN if [ ! -f "/var/www/html/blocklist/argus-ipsets.cdb" ]; then \
        RUN /bin/bash /var/www/html/script/argus-blocklist.sh; \
    fi

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

CMD cron && php-fpm