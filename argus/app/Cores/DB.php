<?php
namespace App\Cores;

/**
 * Helper class untuk membuat QueryBuilder instance
 */
class DB
{
    private static $connection;
    
    public static function setConnection($connection)
    {
        self::$connection = $connection;
    }
    
    public static function table(string $table): QueryBuilder
    {
        return (new QueryBuilder(self::$connection))->table($table);
    }
    
    public static function from(string $table, string $alias = null): QueryBuilder
    {
        return (new QueryBuilder(self::$connection))->from($table, $alias);
    }
    
    public static function raw(string $query, array $bindings = []): array
    {
        return (new QueryBuilder(self::$connection))->raw($query, $bindings);
    }
    
    public static function beginTransaction(): bool
    {
        return self::$connection->beginTransaction();
    }
    
    public static function commit(): bool
    {
        return self::$connection->commit();
    }
    
    public static function rollback(): bool
    {
        return self::$connection->rollback();
    }
}