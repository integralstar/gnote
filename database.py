import firebase_admin
from firebase_admin import credentials, db

cred = credentials.Certificate('/Users/seaofglass/project/gnote/gnote-8e4ef-firebase-adminsdk-pbixg-49916beb00.json')

firebase_admin.initialize_app(cred,{
    'databaseURL':'https://gnote-8e4ef-default-rtdb.firebaseio.com/test'
})

# ref = db.reference('/')
# print(ref.get()['test'])

root = db.reference()
new_user = root.child('user')

default_category = 'basic'
category = ''

keyword = 'AI'

# Create
new_user.child(default_category).set({'keyword': keyword})

# Read
new_user.child(default_category).get()

# Update
# new_user.child(uname).update({'keyword': keyword})
ref = db.reference('강좌/파이썬')
ref.update({'파이썬 Flask로 웹 입문' : 'complete'})


# Delete
deleteV = root.child('users/').child(uname)
deleteV.delete()
