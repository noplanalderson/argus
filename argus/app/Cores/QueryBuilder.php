<?php
namespace App\Cores;


class QueryBuilder
{
    private $connection;
    private $table;
    private $fields = [];
    private $values = [];
    private $wheres = [];
    private $joins = [];
    private $orderBy = [];
    private $groupBy = [];
    private $havings = [];
    private $limit;
    private $offset;

    public function __construct($connection)
    {
        $this->connection = $connection;
    }

    /* ============= CORE ============= */
    public function table(string $table): self
    {
        $this->table = $table;
        return $this;
    }

    public function from(string $table, ?string $alias = null): self
    {
        $this->table = $alias ? "{$table} as {$alias}" : $table;
        return $this;
    }

    private function extractTableName(string $table): string
    {
        if (stripos($table, ' as ') !== false) {
            return trim(explode(' as ', $table)[0]);
        }
        if (strpos($table, ' ') !== false && stripos($table, 'join') === false) {
            return trim(explode(' ', $table)[0]);
        }
        return trim($table);
    }

    private function protectIdentifier(string $column): string
    {
        // jangan bungkus kalau mengandung fungsi, alias, atau dot
        if (preg_match('/[()\s.]/', $column)) {
            return $column;
        }
        return "`{$column}`";
    }

    /* ============= INSERT ============= */
    public function insert(array $data): bool
    {
        $this->fields = array_keys($data);
        $this->values = array_values($data);

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

    /* ============= SELECT ============= */
    public function select($columns = ['*']): self
    {
        $this->fields = is_string($columns) ? [$columns] : $columns;
        return $this;
    }

    public function selectRaw(string $expression): self
    {
        $this->fields[] = $expression;
        return $this;
    }

    /* ============= WHERE ============= */
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
            'boolean' => 'AND',
            'raw' => false
        ];
        return $this;
    }


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
            'boolean' => 'OR',
            'raw' => false
        ];

        return $this;
    }


    public function whereIn(string $column, array $values): self
    {
        $this->wheres[] = [
            'column' => $column,
            'operator' => 'IN',
            'value' => $values,
            'boolean' => 'AND',
            'raw' => false
        ];
        return $this;
    }

    public function whereRaw(string $expression, array $bindings = [], string $boolean = 'AND'): self
    {
        $this->wheres[] = [
            'raw' => true,
            'expression' => $expression,
            'bindings' => $bindings,
            'boolean' => $boolean
        ];
        return $this;
    }

    /* ============= JOIN, ORDER, GROUP, HAVING ============= */
    public function join(string $table, string $relation, string $mode = 'INNER'): self
    {
        $mode = strtoupper($mode);
        if (!in_array($mode, ['INNER', 'LEFT', 'RIGHT', 'FULL'])) {
            throw new \InvalidArgumentException("Invalid JOIN mode: {$mode}");
        }
        $this->joins[] = "{$mode} JOIN {$table} ON {$relation}";
        return $this;
    }


    public function orderBy(string $column, string $direction = 'ASC'): self
    {
        $direction = strtoupper($direction);
        if (!in_array($direction, ['ASC', 'DESC'])) {
            throw new \InvalidArgumentException("Invalid ORDER BY direction: {$direction}");
        }
        $this->orderBy[] = $this->protectIdentifier($column) . " {$direction}";
        return $this;
    }

    public function groupBy(string $column): self
    {
        $this->groupBy[] = $this->protectIdentifier($column);
        return $this;
    }

    public function having(string $column, string $operator, $value): self
    {
        $this->havings[] = [
            'column' => $column,
            'operator' => $operator,
            'value' => $value
        ];
        return $this;
    }


    public function limit(int $limit, int $offset = 0): self
    {
        $this->limit = $limit;
        $this->offset = $offset;
        return $this;
    }

    /* ============= EXECUTE ============= */
    public function get(): array
    {
        $sql = $this->buildSelectQuery();
        $stmt = $this->connection->prepare($sql['query']);
        $stmt->execute($sql['bindings']);

        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }


    public function first(): ?array
    {
        $this->limit(1);
        $results = $this->get();
        return $results[0] ?? null;
    }


    public function count(): int
    {
        $originalFields = $this->fields;
        $this->fields = ['COUNT(*) as count'];

        $result = $this->first();
        $this->fields = $originalFields;

        return (int) ($result['count'] ?? 0);
    }


    public function update(array $data): bool
    {
        if (empty($this->wheres)) {
            throw new \Exception("UPDATE without WHERE is not allowed");
        }

        $tableName = $this->extractTableName($this->table);

        $setParts = [];
        $bindings = [];

        foreach ($data as $key => $value) {
            $setParts[] = "`{$key}` = :set_{$key}";
            $bindings[":set_{$key}"] = $value;
        }

        $sql = "UPDATE `{$tableName}` SET " . implode(', ', $setParts);
        $whereClause = $this->buildWhereClause();
        $sql .= ' WHERE ' . $whereClause['clause'];
        $bindings = array_merge($bindings, $whereClause['bindings']);

        $stmt = $this->connection->prepare($sql);
        return $stmt->execute($bindings);
    }


    public function delete(): bool
    {
        if (empty($this->wheres)) {
            throw new \Exception("DELETE without WHERE is not allowed");
        }

        $tableName = $this->extractTableName($this->table);

        $sql = "DELETE FROM `{$tableName}`";
        $whereClause = $this->buildWhereClause();
        $sql .= ' WHERE ' . $whereClause['clause'];
        $stmt = $this->connection->prepare($sql);
        return $stmt->execute($whereClause['bindings']);
    }

    /* ============= BUILD QUERY ============= */
    private function buildSelectQuery(): array
    {
        $fields = empty($this->fields) ? ['*'] : $this->fields;
        $fieldStr = implode(', ', $fields);

        $sql = "SELECT {$fieldStr} FROM {$this->table}";
        $bindings = [];

        if (!empty($this->joins)) {
            $sql .= ' ' . implode(' ', $this->joins);
        }


        if (!empty($this->wheres)) {
            $whereClause = $this->buildWhereClause();
            $sql .= ' WHERE ' . $whereClause['clause'];
            $bindings = $whereClause['bindings'];
        }
        if (!empty($this->groupBy)) {
            $sql .= ' GROUP BY ' . implode(', ', $this->groupBy);
        }
        if (!empty($this->havings)) {
            $havingClauses = [];
            foreach ($this->havings as $i => $having) {
                $bindKey = ":having_{$i}";
                $havingClauses[] = $this->protectIdentifier($having['column']) . " {$having['operator']} {$bindKey}";
                $bindings[$bindKey] = $having['value'];
            }
            $sql .= ' HAVING ' . implode(' AND ', $havingClauses);
        }
        if (!empty($this->orderBy)) {
            $sql .= ' ORDER BY ' . implode(', ', $this->orderBy);
        }

        if ($this->limit !== null) {
            $sql .= " LIMIT {$this->limit}";
            if ($this->offset > 0) {
                $sql .= " OFFSET {$this->offset}";
            }
        }

        return ['query' => $sql, 'bindings' => $bindings];
    }


    private function buildWhereClause(): array
    {
        $clauses = [];
        $bindings = [];
        $bindingCounter = 0;

        foreach ($this->wheres as $i => $where) {
            $boolean = $i === 0 ? '' : " {$where['boolean']} ";

            if (!empty($where['raw'])) {
                $clauses[] = $boolean . "({$where['expression']})";
                foreach ($where['bindings'] as $bindKey => $val) {
                    $bindings[$bindKey] = $val;
                }
                continue;
            }

            if ($where['operator'] === 'IN') {
                $inPlaceholders = [];
                foreach ($where['value'] as $val) {
                    $bindKey = ":where_in_{$bindingCounter}";
                    $inPlaceholders[] = $bindKey;
                    $bindings[$bindKey] = $val;
                    $bindingCounter++;
                }
                $clauses[] = $boolean . $this->protectIdentifier($where['column']) . " IN (" . implode(',', $inPlaceholders) . ")";
            } else {
                $bindKey = ":where_{$bindingCounter}";
                $clauses[] = $boolean . $this->protectIdentifier($where['column']) . " {$where['operator']} {$bindKey}";
                $bindings[$bindKey] = $where['value'];
                $bindingCounter++;
            }
        }

        return ['clause' => implode('', $clauses), 'bindings' => $bindings];
    }

    /* ============= UTILITIES ============= */
    public function reset(): self
    {
        $this->fields = [];
        $this->values = [];
        $this->wheres = [];
        $this->joins = [];
        $this->orderBy = [];
        $this->groupBy = [];
        $this->havings = [];
        $this->limit = null;
        $this->offset = 0;

        return $this;
    }


    public function beginTransaction(): bool
    {
        return $this->connection->beginTransaction();
    }


    public function commit(): bool
    {
        return $this->connection->commit();
    }


    public function rollback(): bool
    {
        return $this->connection->rollback();
    }

    
    public function raw(string $query, array $bindings = []): array
    {
        $stmt = $this->connection->prepare($query);
        $stmt->execute($bindings);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function toSql(): string
    {
        $sql = $this->buildSelectQuery();
        return $sql['query'];
    }

    public function dumpSql(): array
    {
        return $this->buildSelectQuery();
    }

    public function toRawSql(): string
    {
        $sql = $this->buildSelectQuery();
        $query = $sql['query'];
        foreach ($sql['bindings'] as $key => $val) {
            $query = str_replace($key, "'".addslashes($val)."'", $query);
        }
        return $query;
    }
}
