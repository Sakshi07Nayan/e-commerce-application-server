const Pool = require('pg').Pool;

const pool = new Pool({
  user: 'postgres',
  password: 'postgresql17',
  host: 'localhost',
  port: 5432,
  database: 'postgres'
});

module.exports =  {pool} ;