CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  severity TEXT,
  source TEXT,
  status TEXT,
  age_days INTEGER
);
