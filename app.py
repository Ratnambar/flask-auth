from flask import Flask, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource, marshal_with
from bson.objectid import ObjectId
import json
from bson.json_util import dumps
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
from flask import make_response,jsonify,request
from sqlalchemy.orm.attributes import flag_modified
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
api = Api(app)


app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI']='mysql+pymysql://root:@localhost/test'
app.config['SQLALCHEMY__TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)



class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	public_id = db.Column(db.String(50), unique=True)
	username = db.Column(db.String(100), unique=True, nullable=False)
	email = db.Column(db.String(100), unique=True,nullable=False)
	password = db.Column(db.String(80))



def token_required(f):
	@wraps(f)
	def decorated(*args,**kwargs):
		token = None
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		if not token:
			return jsonify({'message': 'Token is missing!'}),401
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message':'Token is invalid!'}),401
		return f(current_user, *args, **kwargs)
	return decorated


	# def __init__(self, username, email):
	# 	self.username = username
	# 	self.email = email


	# def __repr__(self):
	# 	return '[%s ,%s, %s]'% (self.id,self.username,self.email)

	# def __str__(self):
	# 	return  "From str method of Test: id is %s username is %s, email is %s" % (self.id,self.username,self.email)





class TodoList(Resource):
	@token_required
	def get(self,current_user):
		records = User.query.all()
		l = []
		for r in records:
			d = {}
			d['public_id'] = r.public_id
			d['username'] = r.username
			d['email'] = r.email
			d['password'] = r.password
			l.append(d)		
		# print(l)
		return jsonify({'users' : l})

	def post(self,current_user):
		data = request.get_json()
		hashed_password = generate_password_hash(data['password'],method='sha256')
		new_user = User(public_id=str(uuid.uuid4()), username = data['username'],email=data['email'],password=hashed_password)
		db.session.add(new_user)
		db.session.commit()
		return jsonify({'message': 'new user created.'})



class Todo(Resource):
	@token_required
	def get(self,current_user,public_id):
		user = User.query.filter_by(public_id=public_id).first()
		if not user:
			return jsonify({"message":"No user found!"})
		else:
			user_data = {}
			user_data['public_id'] = user.public_id
			user_data['username'] = user.username
			user_data['email'] = user.email
			user_data['password'] = user.password
			return jsonify({'user_data' : user_data})

	def delete(self,current_user,public_id):
		user = User.query.filter_by(public_id=public_id).first()
		if not user:
			return jsonify({'message':'No user found.'})
		db.session.delete(user)
		db.session.commit()
		return jsonify({'message ': 'This user has been deleted.'})

	def put(self,current_user,public_id):
		data = request.get_json()
		user = User.query.filter_by(public_id=public_id).update(dict(username=data['username'], email=data['email'],password=data['password']))
		db.session.commit()
		return jsonify({'message':'User is updated successfully!.'})


class Login(Resource):
	@token_required
	def get(self,current_user):
		auth = request.authorization
		# print(auth.username)
		if not auth or not auth.username or not auth.password:
			return make_response('Could not verify',401,{'www-Authenticate':'Basic realm="Login required!"'})
		
		user = User.query.filter_by(username=auth.username).first()
		print(user.username)

		if not user:
			return make_response('Could not verify',401,{'www-Authenticate':'Basic realm="Login required!"'})
		
		if check_password_hash(user.password, auth.password):
			
			token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
			print(token)
			return jsonify({'token': token.decode('UTF-8')})
		
		return make_response('Could not verify',401,{'www-Authenticate':'Basic realm="Login required!"'})




api.add_resource(TodoList, '/')
api.add_resource(Todo, '/<public_id>')
api.add_resource(Login, '/login')

if __name__=='__main__':
	app.run(debug=True)