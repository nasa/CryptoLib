import mysql.connector
from mysql.connector import Error

def compare(arr1, arr2):
    if (len(arr1) != len(arr2)):
        print(f'Length Mismatch:\n/
              \tarr1={len(arr1)}\n/
              \tarr2={len(arr2)}')
        return -1
    
    for i, item in enumerate(arr1):
        if (arr1[i] != arr2[i]):
            print(f'Value Mismatch:\n/
              \tarr1{i}={arr1[i]}\n/
              \tarr2{i}={arr2[i]}')
        return -1
    print("Arrays match!")
    return 0

class Database:
    def __init__(self, host:str, port:int, db_name:str, table_name:str, user:str, password:str):
        self.host=host
        self.port=port
        self.database=db_name
        self.table=table_name
        self.user=user
        self.password=password
        self.data=[]
        
    def fetch_all_data(self):
        try:
            # Define the connection details
            self.connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )

            if self.connection.is_connected():
                print("Connected to the database")
                
                # Create a cursor object
                self.cursor = self.connection.cursor()

                # Execute a query to fetch all data from a table
                query = f'SELECT * FROM {self.table}'
                self.cursor.execute(query)

                rows = self.cursor.fetchall()
                for row in rows:
                    self.data.append(row)
                
                self.close_connection()
                return self.data
        
        except Error as e:
            print(f"Error: {e}")

    def close_connection(self):
        if self.connection.is_connected():
            self.cursor.close()
            self.connection.close()
            print("MySQL connection is closed")


if __name__ == "__main__":
    something=Database("localhost", 3306, "db_name", "table_name", "user", "pass")
    db_data = something.fetch_all_data()

    something2=Database("localhost", 3306, "db_name", "table_name", "user", "pass")
    db_data2 = something.fetch_all_data()

    compare(db_data, db_data2)