-- Create a sample table for employees
CREATE TABLE employees (
  id INT PRIMARY KEY,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  email VARCHAR(100),
  hire_date DATE,
  salary DECIMAL(10, 2)
);

-- Insert some sample data
INSERT INTO employees (id, first_name, last_name, email, hire_date, salary)
VALUES 
  (1, 'John', 'Doe', 'john.doe@example.com', '2023-01-15', 75000.00),
  (2, 'Jane', 'Smith', 'jane.smith@example.com', '2023-02-01', 82000.00),
  (3, 'Mike', 'Johnson', 'mike.j@example.com', '2023-03-10', 65000.00);

-- Sample SELECT query
SELECT first_name, last_name, salary 
FROM employees 
WHERE salary > 70000 
ORDER BY salary DESC;