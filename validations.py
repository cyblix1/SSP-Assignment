import re

#input validations
class Validations:
    #using regex
    def validate_password(password):
        #Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
        reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]){8,20}$"
        # compiling regex
        pat = re.compile(reg)
        # searching regex                 
        mat = re.search(pat, password)
        # validating conditions
        if mat:
            return False
        else:
            #check for special characters, regex filtering doesnt work
            special = ['$','@','#','!','*','^','%']
            not_allowed = ['<','>','&']
            if not any(char in special for char in password):
                return False
            else:
                #checks for script tags
                not_allowed = ['<','>','&']
                if not any(char in not_allowed for char in password):
                    return True
                else:
                    return False

    def validate_stuff(stuff):
        not_allowed = ['<','>','&']
        if not any(char in not_allowed for char in stuff):
            return False
        else:
            return True

    #validate email
    def validate_email(email):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if(re.fullmatch(regex, email)):
            return True
        else:
            return False

    #validate security answer
    def validate_answer(answer):
            regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')

            if(regex.search(answer) == None):
                return True
            else:
                return False
         


