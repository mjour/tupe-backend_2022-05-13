const mysql = require("mysql");
let con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "tupe",
  port: 3306
});
  con.connect(function(err) {
    if (err) {
      console.log("Connection failed");
    } else {
      console.log("Connected!");
    }
  });

  module.exports = con;
