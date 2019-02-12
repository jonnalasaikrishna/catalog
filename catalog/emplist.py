from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Role, Base, Employees, User

engine = create_engine('sqlite:///employee.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

user1 = User(name="balujonnala", email="balujonnala222@gmail.com")
session.add(user1)
session.commit()
# Menu for cse
role1 = Role(rolename="Web Design", user_id=1)

session.add(role1)
session.commit()

employee1 = Employees(name="Sai", role=role1, user_id=1)

session.add(employee1)
session.commit()
employee2 = Employees(name="Krishna", role=role1, user_id=1)

session.add(employee2)
session.commit()

role2 = Role(rolename="Developer", user_id=1)

session.add(role2)
session.commit()


employee1 = Employees(name="Balu",  role=role2, user_id=1)

session.add(employee1)
session.commit()
employee2 = Employees(name="Veera", role=role2, user_id=1)

session.add(employee2)
session.commit()
print ("added employees data !")
