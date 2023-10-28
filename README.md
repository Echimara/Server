## Extending a Jwks Server to Employ SQLITE3 Database
The server ```main.py``` uses a pre-written table schema to query a database ```totally_not_my_privateKeys.db```.
The table schema:

```
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```
The ```POST:/auth``` and ```GET:/.well-known/jwks.json``` endpoints have been updated as such:
<br>

#### Under ```POST:/auth``` endpoint:
<ul>
<li>If the “expired” query parameter is not present, a valid (unexpired) key is read.</li>
<li>If the “expired” query parameter is present, an expired key is read.</li>
</ul>

#### Under ```GET:/.well-known/jwks.json``` endpoint:
<ul>
  <li>All valid (non-expired) private keys are read from the DB.</li>
  <li>A JWKS response is created from those private keys.</li>
</ul>

#### Server Usage Requirements:
pip install cryptography==41.0.4
<br>
pip install pyjwt==2.8.0
