# -------------------------------------------------------------------
# Dockerfile for the Laravel backend (SarangTV K‑drama Watchlist)
# -------------------------------------------------------------------

# ---------- 1️⃣ Builder stage: PHP 8.3 with required extensions ----------
FROM php:8.4-fpm-alpine AS builder

# Install system packages and PHP extensions (including zip)
RUN apk add --no-cache \
    git \
    zip \
    unzip \
    libzip-dev \
    curl \
    libpng-dev \
    libjpeg-turbo-dev \
    freetype-dev \
    icu-dev \
    oniguruma-dev \
    libxml2-dev \
    gmp-dev \
    npm \
    mariadb-client \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
    bcmath \
    gd \
    intl \
    pdo_mysql \
    xml \
    opcache \
    zip \
    && apk del gcc g++ make autoconf linux-headers \
    && rm -rf /var/cache/apk/*

# Enable opcache (good for dev)
RUN printf "opcache.enable=1\nopcache.memory_consumption=128\nopcache.interned_strings_buffer=8\nopcache.max_accelerated_files=4000\nopcache.validate_timestamps=1\nopcache.revalidate_freq=2\n" > /usr/local/etc/php/conf.d/opcache-recommended.ini
# -------------------------------------------------------------------
# Composer install (cached layer)
# -------------------------------------------------------------------
WORKDIR /var/www/html
COPY composer.json composer.lock ./
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && composer install --no-dev --no-scripts --optimize-autoloader --no-interaction --prefer-dist

# ------------------------------------------------------------
# 3️⃣ Node / Vite dependencies (cached layer)
# ------------------------------------------------------------
COPY package.json package-lock.json* ./
RUN npm install

# ------------------------------------------------------------
# 4️⃣ Copy the rest of the application & build Vite assets
# ------------------------------------------------------------
COPY . .
RUN npm run build && php artisan package:discover --ansi

# -------------------------------------------------------------------
# Permissions for storage & bootstrap/cache
# -------------------------------------------------------------------
RUN chown -R www-data:www-data storage bootstrap/cache \
    && chmod -R 775 storage bootstrap/cache

# -------------------------------------------------------------------
# Entrypoint script – wait for MySQL, run migrations & storage:link, then serve
# -------------------------------------------------------------------
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# -------------------------------------------------------------------
# Runtime stage – lighter image
# -------------------------------------------------------------------
FROM php:8.4-fpm-alpine AS runtime
WORKDIR /var/www/html

# Install runtime libraries for PHP extensions & mariadb-client
RUN apk add --no-cache \
    mariadb-client \
    libpng \
    libjpeg-turbo \
    freetype \
    icu-libs \
    libzip

# Copy PHP extensions & config from builder
COPY --from=builder /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=builder /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=builder /usr/local/bin/composer /usr/local/bin/composer

# Copy app code and entrypoint
COPY --from=builder /var/www/html /var/www/html
COPY --from=builder /usr/local/bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]

# Default command (overridden by entrypoint if needed)
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
