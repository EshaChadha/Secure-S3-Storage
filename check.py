import boto3
import os
import datetime
from pathlib import Path
import pytz
import botocore
import requests

#Check for buckets public access
def s3_bucket_access_check(s3_client, bucket_name):
	
	bucket_public = s3_client.get_public_access_block(Bucket=bucket_name)

	if 'PublicAccessBlockConfiguration' in bucket_public:
            public_access_block_config = bucket_public['PublicAccessBlockConfiguration']
            if (
                not public_access_block_config.get('BlockPublicAcls', False) or
                not public_access_block_config.get('BlockPublicPolicy', False) or
                not public_access_block_config.get('IgnorePublicAcls', False) or
                not public_access_block_config.get('RestrictPublicBuckets', False)
            ):
                print_bullet(Color.RED + 'Bucket Name: ' + bucket_name + " - Bucket has public access enabled." + Color.END)

            else:
            	print_bullet(Color.GREEN + "Bucket Name: " + bucket_name + " - No public access issues found." + Color.END)

#Checks s3_bucket_policy_permissions
def s3_bucket_policy_permissions(s3_client, bucket_name):
	try:
		bucket_policy = s3_client.get_bucket_policy(Bucket=bucket_name)
	except Exception as e:
		if "The bucket policy does not exist" in str(e):
			bucket_policy = "N/A"
			print_bullet(Color.YELLOW + 'Bucket Name: ' + bucket_name + ' - No bucket policy found attached.' + Color.END)

#Checks bucket not touched since 90 days
def s3_untouched(s3_client, bucket_name):
	timelimit = datetime.datetime.now(pytz.UTC) - datetime.timedelta(days=90)
	last_activity = 'N/A'
	object_list = s3_client.list_objects_v2(Bucket=bucket_name,FetchOwner=True)
	if 'Contents' in object_list:
		for object in object_list['Contents']:
			if last_activity == 'N/A' or last_activity > object['LastModified']:
				last_activity = object['LastModified']
		if last_activity.date() < datetime.datetime.now().date():
			days = (datetime.datetime.now(pytz.UTC) - last_activity).days
			if days > 90:
				print_bullet(Color.RED + 'Bucket Name: ' + bucket_name + ' - Used ' + str(days) + ' days ago.'+ Color.END)

#Checks default server side encryption of bucket
def s3_encryption_check(s3_client, bucket_name):
	bucket_encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
	if 'ServerSideEncryptionConfiguration' not in bucket_encryption:
		print_bullet(Color.RED + "Bucket Name:" + bucket_name + ' - Server-side encryption is not enabled.' + Color.END)
		print("  Checking objects in bucket...")

		object_list = s3_client.list_objects_v2(Bucket=bucket_name)
		if 'Contents' in object_list:
			for object in object_list['Contents']:
				key = object['Key']
				object_metadata = s3_client.head_object(Bucket=bucket_name, Key=key)
				if 'ServerSideEncryption' not in object_metadata:
					print_bullet(Color.RED + "Object " + key + " is unencrypted." + Color.END)
					print ()
	else:
		print_bullet(Color.GREEN + "Bucket Name: " + bucket_name + " - No encryption issues found." + Color.END)

#Checks logging Server Access Logging
def s3_logging_enabled_check(s3_client, bucket_name):
	bucket_logging = s3_client.get_bucket_logging(Bucket=bucket_name)
	if 'LoggingEnabled' not in bucket_logging:
		print_bullet(Color.YELLOW + 'Bucket Name: ' + bucket_name + ' - Access logging is not enabled.' + Color.END)
	else:
		print_bullet(Color.GREEN + "Bucket Name: " + bucket_name + " - Access logging is enabled." + Color.END)

#Object ACL check
def object_access_check(s3_client, bucket_name):
	object_list = s3_client.list_objects_v2(Bucket=bucket_name,FetchOwner=True)
	if 'Contents' in object_list:
		for object in object_list['Contents']:
			object_Owner = object['Owner']
			key = object['Key']
			config = botocore.client.Config(signature_version=botocore.UNSIGNED)
			object_url = boto3.client('s3', config=config).generate_presigned_url('get_object', Params={'Bucket': bucket_name, 'Key': key})
			resp = requests.get(object_url)
			if resp.status_code == 200:
			    print_bullet(Color.RED + 'The object ' + key + ' is public in bucket ' + bucket_name + Color.END)
	else:
		print_bullet(Color.YELLOW + 'Found empty bucket ' + bucket_name + Color.END)

#Check if Bucket Versioning is enabled
def s3_bucket_versioning_check(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if 'Status' in response and response['Status'] == 'Enabled':
            print_bullet(Color.GREEN + 'Bucket Name:' + bucket_name + ' - Bucket versioning is enabled' + Color.END)
        else:
        	print_bullet(Color.RED + 'Bucket Name:' + bucket_name + ' - Bucket versioning is not enabled' + Color.END)
    except Exception as e:
        print('Error:', str(e))

#Check for MFA Delete
def s3_mfa_delete_check(s3_client, bucket_name):
	mfa_check = s3_client.get_bucket_versioning(Bucket=bucket_name)
	if 'MFADelete' in mfa_check and mfa_check['MFADelete'] == 'Enabled':
		print_bullet(Color.GREEN + 'Bucket Name: ' + bucket_name + " - MFA Delete is enabled" + Color.END)
	else:
		print_bullet(Color.RED + 'Bucket Name: ' + bucket_name + " - MFA Delete is not enabled" + Color.END)


#Get all AWS account profiles from aws credentials file
def get_profiles(cred_file):
	profiles = []
	try:
		with open(cred_file) as f:
			for line in f.readlines():
				if '[' in line:
					line = line.replace('[','').replace(']','').strip('\n')
					profiles.append(line)
	except Exception as e:
		print ("Error:" + str(e))
	return profiles

#Get default home dir of user executing the script
def get_home_dir():
    home_dir = str(Path.home())
    return home_dir

def main():
	home_dir = get_home_dir()
	cred_file_path = home_dir + '\\.aws\\credentials'

	#Checks if aws credential file exists and get all AWS account profiles
	if os.path.exists(cred_file_path):
		profile_names = get_profiles(cred_file_path)
	else:
		cred_file_path = raw_input("Please enter credential files absolute path: ")
		profile_names = get_profiles(cred_file_path)

	print_heading("\t\t\tAWS S3 Security Checks")
	print ("\t\t\t----------------------\n\n")
	for profile in profile_names:
		print ("Account " + profile.upper())
		print ("-----------------")
		print ()
		session = boto3.session.Session(profile_name = profile)
		s3_client = session.client('s3')
		try:
			bucket_list = s3_client.list_buckets()
			print ("\t\t\tBucket & Object Access Check")
			print ("\t\t\t----------------------------")
			for bucket in bucket_list['Buckets']:
				s3_bucket_access_check(s3_client, bucket['Name'])
				object_access_check(s3_client, bucket['Name'])			
			print ()
			print ("\t\t\tBucket Encryption Check")
			print ("\t\t\t-----------------------")
			for bucket in bucket_list['Buckets']:
				s3_encryption_check(s3_client, bucket['Name'])
			print ()
			print ("\t\t\tBucket Access Logging Check")
			print ("\t\t\t---------------------------")
			for bucket in bucket_list['Buckets']:
				s3_logging_enabled_check(s3_client, bucket['Name'])
			print ()
			print ("\t\t\tBucket Versioning Check")
			print ("\t\t\t-----------------------")
			for bucket in bucket_list['Buckets']:
				s3_bucket_versioning_check(s3_client, bucket['Name'])
			print ()
			print ("\t\t\tMFA Delete Check")
			print ("\t\t\t----------------")
			for bucket in bucket_list['Buckets']:
				s3_mfa_delete_check(s3_client, bucket['Name'])
			print ()
			print ("\t\t\tBucket Policy Check")
			print ("\t\t\t-------------------")
			for bucket in bucket_list['Buckets']:
				s3_bucket_policy_permissions(s3_client, bucket['Name'])
			print ()
			print ("\t\t\tBuckets Not Used in 90 Days")
			print ("\t\t\t---------------------------")
			for bucket in bucket_list['Buckets']:
				s3_untouched(s3_client, bucket['Name'])
			print ()
		
		except Exception as e:
			if 'AccessDenied' in str(e):
				print ('ERROR: Insufficient permissions to access S3 buckets for account ' + profile + '.')
			else:
				print ('ERROR: ' + str(e))	

	   		
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_heading(heading):
    print(Color.BOLD + heading + Color.END)

def print_bullet(text):
    bullet = "\u2022"  # Unicode bullet point character
    print(f"{bullet} {text}")

if __name__ == '__main__':
	main()
