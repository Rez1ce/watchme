import secrets
import os
from typing import Optional
import psycopg2
from datetime import *
import calendar
import sys
from fastapi import Depends, FastAPI, HTTPException, status, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, File, UploadFile
import base64
import uvicorn
import telebot
#from passlib.hash import pbkdf2_sha256
#hash = pbkdf2_sha256.hash("toomanysecrets") #take hash from pass



app = FastAPI()

security = HTTPBasic()

origins = ['*']
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
templates = Jinja2Templates(directory="templates")

SECRET_KEY = "8e8649528b788363df300834cbeb58688e484eab29564ee77b2043aafaa685df"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
app.mount("/vendor", StaticFiles(directory="vendor"), name="vendor")
app.mount("/css", StaticFiles(directory="css"), name="css")
app.mount("/fonts", StaticFiles(directory="fonts"), name="fonts")
app.mount("/images", StaticFiles(directory="images"), name="images")
app.mount("/js", StaticFiles(directory="js"), name="js")
fake_users_db = {
    "johndoe": {
        "username": "johndoe@ex.ru",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$mQOQvYU9BFlLqCX3U14w.eXlJ724CS6qozpvShJczFIWJQ3B6zH5m",
        #"hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
        "rez": {
        "username": "rez@ex.ru",
        "full_name": "rez zer0",
        "email": "cool@example.com",
        "hashed_password": "$2b$12$kZPHupT7Qllc3vJgQiYAs.KIJlpue1zrrfVOVHWLNuKtUNa/Ebmny",
        "disabled": False,
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


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def pgsql_update(date, name_q):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    time_table = []
    time_table_fixed = []
    postgreSQL_select_Query = "select * from scrshot WHERE date = '" + date + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall() 
    if(len(tabel_records) == 0):
        error = 'No data for this date'
        return True

    i=0
    tabel_records = sorted(tabel_records, key=lambda ob: ob[5])
    for row in tabel_records:
        time_table.append(row[5][:8])
        i+=1

    temp_h = 999
    temp_m = 999
    temp_s = 999
    for time in time_table:
        time_z = datetime.strptime(time, "%H:%M:%S")
        if(time_z.hour <= temp_h):
            temp_h = time_z.hour
            if(time_z.minute <= temp_m):
                temp_m = time_z.minute
                if(time_z.second <= temp_s):               
                    temp_s = time_z.second
        minimum = [temp_h,temp_m,temp_s]
    temp_h = 0
    temp_m = 0
    temp_s = 0
    for time2 in time_table:
        time_z = datetime.strptime(time2, "%H:%M:%S")
        if(time_z.hour >= temp_h):
            temp_h = time_z.hour
            if(time_z.minute >= temp_m):
                temp_m = time_z.minute
                if(time_z.second >= temp_s):
                    temp_s = time_z.second
        maximum = [temp_h,temp_m,temp_s]
    i = 0
    act = [0,0,0] # H:M:S
    nonact = [0,0,0]
    for n in time_table:
        if(i>=len(time_table)-1):
            i-=1
        time_minutes_now = datetime.strptime(time_table[i+1], "%H:%M:%S")
        time_minutes_bef = datetime.strptime(n, "%H:%M:%S")
        delt = str(time_minutes_now - time_minutes_bef)
        delt = datetime.strptime(delt, "%H:%M:%S")
        if (delt <= datetime.strptime("0:03:00", "%H:%M:%S")):
            act[0] += delt.hour
            act[1] += delt.minute
            act[2] += delt.second
        else:
            nonact[0] += delt.hour
            nonact[1] += delt.minute
            nonact[2] += delt.second
        i+=1

    act_str = str(timedelta(hours=act[0], minutes=act[1], seconds=act[2]))
    nonact_str = str(timedelta(hours=nonact[0], minutes=nonact[1], seconds=nonact[2]))
    minimum_str = str(timedelta(hours=minimum[0], minutes=minimum[1], seconds=minimum[2]))
    maximum_str = str(timedelta(hours=maximum[0], minutes=maximum[1], seconds=maximum[2]))

    tabel_records_q=[]
    postgreSQL_query = "select * from working_hours WHERE date = '" + date + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_query)
    tabel_records_q = cursor.fetchall() 

    if (len(tabel_records_q)==0):
        postgreSQL_query = "INSERT INTO working_hours (name,date,time_start,time_end,active,non_active) VALUES ('"+str(tabel_records[0][2])+"', '"+str(date)+"', '"+str(tabel_records[0][5])+"', '"+str(tabel_records[len(tabel_records)-1][5])+"', '"+act_str+"', '"+nonact_str+"')"
        print("===INSERTED===")

    else:
        postgreSQL_query = "UPDATE working_hours SET active='"+ act_str +"' WHERE date='"+ date +"' and name='"+ name_q +"';"\
        + "UPDATE working_hours SET non_active='"+ nonact_str +"' WHERE date='"+ date +"' and name='"+ name_q +"';"\
        + "UPDATE working_hours SET time_end='"+ str(tabel_records[len(tabel_records)-1][5]) +"' WHERE date='"+ date +"' and name='"+ name_q +"'"
        print("===UPDATED===")

    cursor.execute(postgreSQL_query)
    connection.commit() # <- We MUST commit to reflect the inserted data
    cursor.close()
    connection.close()
    return False

def onlypidmas(mas):
    i = 0
    j = 1
    while(i < len(mas) - 1):
        j = i + 1
        while(j <= len(mas) - 1):
            if(mas[i][0] == mas[j][0]):
                curTime = datetime.strptime(mas[i][2][:8], "%H:%M:%S")
                nextTime = datetime.strptime(mas[j][2][:8], "%H:%M:%S")
                delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) + timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
                mas[i][2] = str(delt)
                mas.pop(j)
                j-=1
            j+=1
        i+=1
    return mas

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
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


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

@app.get("/items/sql")
def read_item(name_req: str, date_req: str):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()

    date_q_list=[]
    date_q = date_req[:10]
    date_q = date_q.replace("-", '.')
    date_q_list = date_q.split('.')
    date_q_list.reverse()
    date_q = '.'.join(date_q_list)
    name_q = name_req

    if(pgsql_update(date_q,name_q)):
        raise HTTPException(status_code=404, detail="Try another name or date")

    postgreSQL_select_Query = "select * from working_hours WHERE date = '" + date_q + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    cursor.close()
    connection.close()
    
    if(len(tabel_records) == 0):
        raise HTTPException(status_code=404, detail="Try another name or date")
    return {"name_usr": name_q, "date":date_q, "active": tabel_records[0][5], "nonactive":tabel_records[0][6], "time_start": tabel_records[0][3], "time_end":tabel_records[0][4]}


@app.get("/takename")
async def takename():
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    postgreSQL_select_Query = "SELECT DISTINCT name from scrshot"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    cursor.close()
    connection.close()
    return{"names": tabel_records}

@app.get("/loginfo")
async def loginfo():
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    postgreSQL_select_Query = "SELECT name, last_login, pass_change from logon_info"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    cursor.close()
    connection.close()
    return{"log_data": tabel_records}

@app.get("/items/alldata")
async def alldata(name_req: str, date_req: str):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    date_q_list=[]
    date_q = date_req[:10]
    date_q = date_q.replace("-", '.')
    date_q_list = date_q.split('.')
    date_q_list.reverse()
    date_q = '.'.join(date_q_list)
    name_q = name_req
    postgreSQL_select_Query = "select name, pid_name, time, pid_header from scrshot WHERE date = '" + date_q + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    cursor.close()
    connection.close()

    return{"alldata": tabel_records}

@app.get("/items/pidwithhead")
async def pidwithhead(name_req: str, date_req: str):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    date_q_list=[]
    date_q = date_req[:10]
    date_q = date_q.replace("-", '.')
    date_q_list = date_q.split('.')
    date_q_list.reverse()
    date_q = '.'.join(date_q_list)
    name_q = name_req
    time_table = []
    sum_delt = timedelta(hours=0,minutes=0,seconds=0)
    postgreSQL_select_Query = "select name, pid_name, time, pid_header from scrshot WHERE date = '" + date_q + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    i = 0
    j = 0
    tabel_records = sorted(tabel_records, key=lambda ob: ob[2])

    while(i < len(tabel_records) - 1 ):
        flag = True
        delt = timedelta(hours=99,minutes=99,seconds=99)
        sum_delt = timedelta(hours=0,minutes=0,seconds=0)
        while((tabel_records[i][1] == tabel_records[i+1][1]) & (tabel_records[i][3] == tabel_records[i+1][3])):
            cur_pid = tabel_records[i][1]
            cur_pid_head = tabel_records[i][3]
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if(str(delt) <=  "0:03:00"):
                sum_delt += delt
            else:
                flag = False
                break
            i+=1
            if(i+1 == len(tabel_records)):
                break
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if((tabel_records[i][1] != tabel_records[i+1][1]) | (tabel_records[i][3] != tabel_records[i+1][3]) | (str(delt) >  "0:03:00")):
                time_table.insert(i, [cur_pid, cur_pid_head,  str(sum_delt)])
                break
        if(i+1 == len(tabel_records)):
            break
        if(((tabel_records[i][1] != tabel_records[i+1][1]) | (tabel_records[i][3] != tabel_records[i+1][3])) & flag):
            cur_pid = tabel_records[i][1]
            cur_pid_head = tabel_records[i][3]
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if(str(delt) <=  "0:03:00"):
                sum_delt = delt
                delt = timedelta(hours=99,minutes=99,seconds=99)
                time_table.insert(i, [cur_pid, cur_pid_head,  str(sum_delt)])

        i+=1
            
    i = 0
    j = 1
    while(i < len(time_table) - 1):
        j = i + 1
        while(j < len(time_table) - 1):
            if((time_table[i][0] == time_table[j][0]) & (time_table[i][1] == time_table[j][1])):
                curTime = datetime.strptime(time_table[i][2][:8], "%H:%M:%S")
                nextTime = datetime.strptime(time_table[j][2][:8], "%H:%M:%S")
                delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) + timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
                time_table[i][2] = str(delt)
                time_table.pop(j)
                j-=1
            j+=1
        i+=1

    cursor.close()
    connection.close()
    return{"pidata": time_table}

@app.get("/items/onlypidinfo")
async def onlypidinfo(name_req: str, date_req: str):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    date_q_list=[]
    date_q = date_req[:10]
    date_q = date_q.replace("-", '.')
    date_q_list = date_q.split('.')
    date_q_list.reverse()
    date_q = '.'.join(date_q_list)
    name_q = name_req
    time_table = []
    sum_delt = timedelta(hours=0,minutes=0,seconds=0)
    postgreSQL_select_Query = "select name, pid_name, time, pid_header from scrshot WHERE date = '" + date_q + "' and name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    i = 0
    j = 0
    tabel_records = sorted(tabel_records, key=lambda ob: ob[2])

    while(i < len(tabel_records) - 1):
        flag = True
        delt = timedelta(hours=99,minutes=99,seconds=99)
        sum_delt = timedelta(hours=0,minutes=0,seconds=0)
        while((tabel_records[i][1] == tabel_records[i+1][1]) & (tabel_records[i][3] == tabel_records[i+1][3])):
            cur_pid = tabel_records[i][1]
            cur_pid_head = tabel_records[i][3]
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if(str(delt) <=  "0:03:00"):
                sum_delt += delt
            else:
                flag = False
                break
            i+=1
            if(i+1 == len(tabel_records)):
                break
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if((tabel_records[i][1] != tabel_records[i+1][1]) | (tabel_records[i][3] != tabel_records[i+1][3]) | (str(delt) >  "0:03:00")):
                time_table.insert(i, [cur_pid, cur_pid_head,  str(sum_delt)])
                break
        if(i+1 == len(tabel_records)):
            break   
        if(((tabel_records[i][1] != tabel_records[i+1][1]) | (tabel_records[i][3] != tabel_records[i+1][3])) & flag):
            cur_pid = tabel_records[i][1]
            cur_pid_head = tabel_records[i][3]
            curTime = datetime.strptime(tabel_records[i][2][:8], "%H:%M:%S")
            nextTime = datetime.strptime(tabel_records[i+1][2][:8], "%H:%M:%S")
            delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) - timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
            if(str(delt) <=  "0:03:00"):
                sum_delt = delt
                delt = timedelta(hours=99,minutes=99,seconds=99)
                time_table.insert(i, [cur_pid, cur_pid_head,  str(sum_delt)])

        i+=1
            
    i = 0
    j = 1
    while(i < len(time_table) - 1):
        j = i + 1
        while(j < len(time_table) - 1):
            if((time_table[i][0] == time_table[j][0]) & (time_table[i][1] == time_table[j][1])):
                curTime = datetime.strptime(time_table[i][2][:8], "%H:%M:%S")
                nextTime = datetime.strptime(time_table[j][2][:8], "%H:%M:%S")
                delt = timedelta(hours=nextTime.hour, minutes=nextTime.minute, seconds=nextTime.second) + timedelta(hours=curTime.hour, minutes=curTime.minute, seconds=curTime.second)
                time_table[i][2] = str(delt)
                time_table.pop(j)
                j-=1
            j+=1
        i+=1

    cursor.close()
    connection.close()
    return{"onlypid":onlypidmas(time_table)}

@app.get("/items/justwork")
async def justwork(name_req: str):
    connection = psycopg2.connect(dbname='postgres', user='postgres', password='321321Aa', host='10.5.37.53')
    cursor = connection.cursor()
    name_q = name_req
    postgreSQL_select_Query = "select date, time_start, time_end, active, non_active from working_hours WHERE name = '" + name_q + "'"
    cursor.execute(postgreSQL_select_Query)
    tabel_records = cursor.fetchall()
    cursor.close()
    connection.close()

    return{"justwork": tabel_records}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
