<?php
namespace App\Cores;

/**
 * Simple Query Builder Library
 * Menyediakan interface yang mudah untuk operasi database CRUD
 */
class QueryBuilder
{
    private $connection;
    private $table;
    private $fields = [];
    private $values = [];
    private $wheres = [];
    private $joins = [];
    private $orderBy = [];
    private $limit;
    private $offset;

    public function __construct($connection)
    {
        $this->connection = $connection;
    }

    /**
     * Set tabel yang akan digunakan
     */
    public function table(string $table): self
    {
        $this->table = $table;
        return $this;
    }
    
    /**
     * Set tabel dengan alias
     */
    public function from(string $table, string|null $alias = null): self
    {
        if ($alias) {
            $this->table = "{$table} as {$alias}";
        } else {
            $this->table = $table;
        }
        return $this;
    }

    /**
     * Insert data ke database
     */
    public function insert(array $data): bool
    {
        $this->fields = array_keys($data);
        $this->values = array_values($data);
        
        // Extract table name without alias for INSERT
        $tableName = $this->extractTableName($this->table);
        
        $placeholders = ':' . implode(', :', $this->fields);
        $fields = '`' . implode('`, `', $this->fields) . '`';
        
        $sql = "INSERT INTO `{$tableName}` ({$fields}) VALUES ({$placeholders})";
        
        $stmt = $this->connection->prepare($sql);
        
        $boundData = [];
        foreach ($data as $key => $value) {
            $boundData[':' . $key] = $value;
        }
        
        return $stmt->execute($boundData);
    }
    
    /**
     * Extract table name from table string (remove alias)
     */
    private function extractTableName(string $table): string
    {
        // Jika ada 'as' atau spasi, ambil bagian pertama
        if (stripos($table, ' as ') !== false) {
            return trim(explode(' as ', $table)[0]);
        }
        
        if (strpos($table, ' ') !== false && stripos($table, 'join') === false) {
            return trim(explode(' ', $table)[0]);
        }
        
        return trim($table);
    }

    /**
     * Insert batch data (multiple rows)
     */
    public function insertBatch(array $dataArray): bool
    {
        if (empty($dataArray)) return false;
        
        $tableName = $this->extractTableName($this->table);
        $fields = array_keys($dataArray[0]);
        $fieldsStr = '`' . implode('`, `', $fields) . '`';
        
        $placeholders = '(' . str_repeat('?,', count($fields) - 1) . '?)';
        $allPlaceholders = str_repeat($placeholders . ',', count($dataArray) - 1) . $placeholders;
        
        $sql = "INSERT INTO `{$tableName}` ({$fieldsStr}) VALUES {$allPlaceholders}";
        
        $stmt = $this->connection->prepare($sql);
        
        $allValues = [];
        foreach ($dataArray as $data) {
            $allValues = array_merge($allValues, array_values($data));
        }
        
        return $stmt->execute($allValues);
    }

    /**
     * Select data dari database
     */
    public function select($columns = ['*']): self
    {
        if (is_string($columns)) {
            $columns = [$columns];
        }
        $this->fields = $columns;
        return $this;
    }

    /**
     * Add WHERE condition
     */
    public function where(string $column, $operator, $value = null): self
    {
        if ($value === null) {
            $value = $operator;
            $operator = '=';
        }
        
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'boolean' => 'AND'
        ];
        
        return $this;
    }

    /**
     * Add OR WHERE condition
     */
    public function orWhere(string $column, $operator, $value = null): self
    {
        if ($value === null) {
            $value = $operator;
            $operator = '=';
        }
        
        $this->wheres[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value,
            'boolean' => 'OR'
        ];
        
        return $this;
    }

    /**
     * Add WHERE IN condition
     */
    public function whereIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IN',
            'value' => $values,
            'boolean' => 'AND'
        ];
        
        return $this;
    }

    /**
     * Add JOIN
     */
    public function join(string $table, string $relation, string $mode = 'inner'): self
    {
        $this->joins[] = "{$mode} JOIN {$table} ON {$relation}";
        return $this;
    }

    /**
     * Add ORDER BY
     */
    public function orderBy(string $column, string $direction = 'ASC'): self
    {
        $this->orderBy[] = "{$column} {$direction}";
        return $this;
    }

    /**
     * Add LIMIT
     */
    public function limit(int $limit, int $offset = 0): self
    {
        $this->limit = $limit;
        $this->offset = $offset;
        return $this;
    }

    /**
     * Execute SELECT query dan return results
     */
    public function get(): array
    {
        $sql = $this->buildSelectQuery();
        $stmt = $this->connection->prepare($sql['query']);
        $stmt->execute($sql['bindings']);
        
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    /**
     * Get single record
     */
    public function first(): ?array
    {
        $this->limit(1);
        $results = $this->get();
        return $results[0] ?? null;
    }

    /**
     * Count records
     */
    public function count(): int
    {
        $originalFields = $this->fields;
        $this->fields = ['COUNT(*) as count'];
        
        $result = $this->first();
        $this->fields = $originalFields;
        
        return (int) ($result['count'] ?? 0);
    }

    /**
     * Update data
     */
    public function update(array $data): bool
    {
        $tableName = $this->extractTableName($this->table);
        
        $setParts = [];
        $bindings = [];
        
        foreach ($data as $key => $value) {
            $setParts[] = "`{$key}` = :set_{$key}";
            $bindings[":set_{$key}"] = $value;
        }
        
        $sql = "UPDATE `{$tableName}` SET " . implode(', ', $setParts);
        
        if (!empty($this->wheres)) {
            $whereClause = $this->buildWhereClause();
            $sql .= ' WHERE ' . $whereClause['clause'];
            $bindings = array_merge($bindings, $whereClause['bindings']);
        }
        
        $stmt = $this->connection->prepare($sql);
        return $stmt->execute($bindings);
    }

    /**
     * Delete data
     */
    public function delete(): bool
    {
        $tableName = $this->extractTableName($this->table);
        
        $sql = "DELETE FROM `{$tableName}`";
        $bindings = [];
        
        if (!empty($this->wheres)) {
            $whereClause = $this->buildWhereClause();
            $sql .= ' WHERE ' . $whereClause['clause'];
            $bindings = $whereClause['bindings'];
        }
        
        $stmt = $this->connection->prepare($sql);
        return $stmt->execute($bindings);
    }

    /**
     * Build SELECT query
     */
    private function buildSelectQuery(): array
    {
        $fields = empty($this->fields) ? ['*'] : $this->fields;
        
        // Handle field selection dengan alias support
        $fieldStr = is_array($fields) ? implode(', ', $fields) : $fields;
        
        $sql = "SELECT {$fieldStr} FROM {$this->table}";
        $bindings = [];
        
        // Add JOINs
        if (!empty($this->joins)) {
            $sql .= ' ' . implode(' ', $this->joins);
        }
        
        // Add WHERE clauses
        if (!empty($this->wheres)) {
            $whereClause = $this->buildWhereClause();
            $sql .= ' WHERE ' . $whereClause['clause'];
            $bindings = $whereClause['bindings'];
        }
        
        // Add ORDER BY
        if (!empty($this->orderBy)) {
            $sql .= ' ORDER BY ' . implode(', ', $this->orderBy);
        }
        
        // Add LIMIT and OFFSET
        if ($this->limit !== null) {
            $sql .= " LIMIT {$this->limit}";
            if ($this->offset > 0) {
                $sql .= " OFFSET {$this->offset}";
            }
        }
        
        return ['query' => $sql, 'bindings' => $bindings];
    }

    /**
     * Build WHERE clause
     */
    private function buildWhereClause(): array
    {
        $clauses = [];
        $bindings = [];
        $bindingCounter = 0;
        
        foreach ($this->wheres as $i => $where) {
            $boolean = $i === 0 ? '' : " {$where['boolean']} ";
            
            if ($where['operator'] === 'IN') {
                $inPlaceholders = [];
                foreach ($where['value'] as $val) {
                    $bindKey = ":where_in_{$bindingCounter}";
                    $inPlaceholders[] = $bindKey;
                    $bindings[$bindKey] = $val;
                    $bindingCounter++;
                }
                $clauses[] = $boolean . "`{$where['column']}` IN (" . implode(',', $inPlaceholders) . ")";
            } else {
                $bindKey = ":where_{$bindingCounter}";
                $clauses[] = $boolean . "`{$where['column']}` {$where['operator']} {$bindKey}";
                $bindings[$bindKey] = $where['value'];
                $bindingCounter++;
            }
        }
        
        return [
            'clause' => implode('', $clauses),
            'bindings' => $bindings
        ];
    }

    /**
     * Reset query builder state
     */
    public function reset(): self
    {
        $this->fields = [];
        $this->values = [];
        $this->wheres = [];
        $this->joins = [];
        $this->orderBy = [];
        $this->limit = null;
        $this->offset = 0;
        
        return $this;
    }

    /**
     * Begin transaction
     */
    public function beginTransaction(): bool
    {
        return $this->connection->beginTransaction();
    }

    /**
     * Commit transaction
     */
    public function commit(): bool
    {
        return $this->connection->commit();
    }

    /**
     * Rollback transaction
     */
    public function rollback(): bool
    {
        return $this->connection->rollback();
    }

    /**
     * Execute raw query
     */
    public function raw(string $query, array $bindings = []): array
    {
        $stmt = $this->connection->prepare($query);
        $stmt->execute($bindings);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }
    
    /**
     * Get the SQL query that would be executed (untuk debugging)
     */
    public function toSql(): string
    {
        $sql = $this->buildSelectQuery();
        return $sql['query'];
    }
    
    /**
     * Get SQL dengan bindings (untuk debugging)
     */
    public function dumpSql(): array
    {
        return $this->buildSelectQuery();
    }
}