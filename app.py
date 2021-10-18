# from datetime import datetime, timedelta
from typing import Optional
import json
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


with open("menu.json","r") as read_file:
	data=json.load(read_file)


SECRET_KEY = "9b0663927c67159be5f9587968529f14f27923e5ae1d231195e12c822ced8d36" 
ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "asdf":{
        "username":"asdf",
        "full_name":"asdfghjkl",
        "email":"dummy@email.com",
        "hashed_password":"$2b$12$naWFMV71ifNuPCNXUhknxuIEwKCPSZ7YfeG0ZelrQpfM9uZa6qLpe",
        "disabled":False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

encrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return encrypt_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if  not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict):#, expires_delta: Optional[timedelta] = None
    to_encode = data.copy()
    # if expires_delta:
    #     expire = datetime.utcnow() + expires_delta
    # else:
    #     expire = datetime.utcnow() + timedelta(minutes=15)
    # to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


#Auth Function
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


#Menu Function
@app.get('/menu') #get all item in menu
async def read_all_menu(current_user: User = Depends(get_current_active_user)):
	return data['menu']

@app.get('/menu/{item_id}') #select the item from menu based on id
async def read_menu(item_id:int,current_user: User = Depends(get_current_active_user)):
	for menu_item in data['menu']:
		if menu_item['id']==item_id:
			return menu_item
	raise HTTPException(
		status_code=404,detail=f'Item not found'
	)

@app.delete('/menu/remove') #to delete an item based on the id
async def delete_menu(item_id:int,current_user: User = Depends(get_current_active_user)):
	for menu_item in data['menu']:
		if menu_item['id']==item_id:
			data['menu'].remove(menu_item)
	read_file.close()
	with open('menu.json', 'w') as outfile:
		json.dump(data, outfile)
	outfile.close()
	return {"message":"Data deleted succesfully"}

@app.put('/menu/update') #to change an item based on user input
async def update_menu(item_id:int,item_name:str,current_user: User = Depends(get_current_active_user)):
	new_list=[]
	for menu_item in data['menu']:
		if menu_item['id']==item_id:
			menu_item['name']=item_name
		new_list.append(menu_item)
	data_dummy={"menu":new_list}
	with open('menu.json', 'w') as outfile:
		json.dump(data_dummy, outfile)
	outfile.close()
	return {"message":"Data updated succesfully"}

@app.post('/menu/add')#to add a new item
async def add_menu(item_name:str,current_user: User = Depends(get_current_active_user)):
	data['menu'].append({'id':len(data['menu'])+1,'name':item_name})
	with open('menu.json', 'w') as outfile:
		json.dump(data, outfile)
	outfile.close()
	return {"message":"data added"}