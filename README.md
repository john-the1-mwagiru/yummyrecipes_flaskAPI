# yummyrecipes_flaskAPI
A Flask RESTful API with endoints that enable users to :
* Register ,login and manage their accounts.
* Create ,update , view and delete their recipe categories.
* Create, update, view and delete their recipes.
* Enable logging of data manipulation timestamps
## Prerequisites
[Python 3.11.4](https://www.python.org/downloads/release/python-3114/) or a later version
## Virtual Environment
Create a virtual environment
```
python -m venv venv
```
Activate virtual environment
```
source venv/bin/activate
```
## Dependencies
Install all project dependencies
```
pip install requirements.txt
```
## Migrations
Run migration by:
```
flask db init
flask db migrate
flask db upgrade
```
## Start the server
```
python app.py
```
## Pagination
The API enables pagination by passing in page and limit as arguments in the request url as shown in the following example:
```
http://127.0.0.1:5000/category?page=1&limit=3
```
## Searching
The API implements searching based on the name using a GET parameter q as shown below:
```
http://127.0.0.1:5000/category?q=example
```
