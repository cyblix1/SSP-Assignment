import mysql.connector
from mysql.connector import Error
from configparser import ConfigParser

#configuration files
file = 'config.properities'
config = ConfigParser()
config.read(file)


 def decrypt(list):
    try:
        connection = mysql.connector.connect(host=config['account']['host'],user=config['account']['user'],database=config['account']['db'],password=config['account']['password'])
        if connection.is_connected(): 
            cursor = connection.cursor()
            