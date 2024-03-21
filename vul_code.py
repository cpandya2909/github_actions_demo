from flask import Flask


app = Flask('vul_code')


app.run(debug=True, host='127.0.1.1', port=5000)
