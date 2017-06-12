# coding=utf-8
import requests
from lxml import html
import re
import sys
import json
import time
import userinfo

timeout = 1
base_url = 'gdjwgl.bjut.edu.cn'
last_result = {}
token = {'token': '0', 'time': 0, 'expire': 0}

def load_last_result():
	global last_result
	global token
	try:
		with open('result.json', 'r') as f_json:
			last_result = json.load(f_json)
		print_log("Last result loaded.")
	except:
		print_log("Last result file not avaliable.")
		
	try:
		with open('token.json', 'r') as f_json:
			token = json.load(f_json)
		print_log("Token loaded.")
	except:
		print_log("Token file not avaliable.")


def retry_post(retry, session, h_url, **kwargs):
	ctTry = 0
	while 1:
		try:
			res = session.post(h_url, **kwargs)
		except:
			if ctTry < retry:
				ctTry += 1
				print_log('Error: Retrying...', ctTry)
				sys.stdout.flush()
			else:
				print_log("Failed to get page. Exiting.")
				sys.exit()
		else:
			break
	return res


def retry_get(retry, session, h_url, **kwargs):
	ctTry = 0
	while 1:
		try:
			res = session.get(h_url, **kwargs)
		except:
			if ctTry < retry:
				ctTry += 1
				print_log('Error: Retrying...', ctTry)
				sys.stdout.flush()
			else:
				print_log("Failed to get page. Exiting.")
				sys.exit()
		else:
			break
	return res

def login(username, password):
	session = requests.Session()
	h_url = 'http://' + base_url + '/default_vsso.aspx'
	h_head = {
		'Content-Type': 'application/x-www-form-urlencoded'
	}
	h_data = {
		'TextBox1': username,
		'TextBox2': password,
		'RadioButtonList1_2': '学生'.encode('gb2312'),
		'Button1': ''
	}
	res = retry_post(30, session, h_url, data=h_data, headers=h_head, timeout=timeout, allow_redirects=False)

	if res.headers["Location"] == '/xs_main.aspx?xh=' + username:
		print_log("Login success.")
	else:
		print_log("Login failed, check password.")
		sys.exit()
	return session

def get_name(session, username):
	h_url = 'http://' + base_url + '/xs_main.aspx?xh=' + username
	r = retry_get(30, session, h_url)
	p = re.compile(r'<span id="xhxm">.+?</span></em>')
	rp = p.findall(r.text)
	return rp[0][16:-14]

def get_viewstate(session, username, name):
	rp = []
	while len(rp) == 0:
		h_url = 'http://' + base_url + '/xscjcx.aspx'
		h_params = {
			'xh': username,
			'xm': name.encode('gb2312'),
			'gnmkdm': 'N121605'
		}
		r = retry_get(30, session, h_url,  params=h_params)
		p = re.compile(r'<input type=\"hidden\" name=\"__VIEWSTATE\" value=\".+?\" />')
		rp = p.findall(r.text)
	return rp[0][47:-4]

def get_score(session, username, name, viewstate):
	h_url = 'http://' + base_url + '/xscjcx.aspx'
	h_params = {
		'xh': username,
		'xm': name.encode('gb2312'),
		'gnmkdm': 'N121605'
	}
	
	h_data = {
		'__EVENTTARGET': '',
		'__EVENTARGUMENT': '',
		'__VIEWSTATE': viewstate,
		'hidLanguage': '',
		'ddlXN': '',
		'ddlXQ': '',
		'ddl_kcxz': '',
		'btn_zcj': '历年成绩'.encode('gb2312')
	}
	r = retry_post(3, session, h_url, params=h_params, data=h_data)
	# form tree
	t = html.fromstring(r.text)
	# view every row
	flag_changed = False
	f_log = open("last_viewed_time.txt", "w")
	for index, tr in enumerate(t.xpath('//table[@id="Datagrid1"]/tr')):
		if index>0 : #bypass the title line
			course = tr.xpath('./td/text()')
			# use year+term+code+name to index a course
			key_name = course[0] + course[1] + course[2] + course[3]
			f_log.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + key_name + '\n')
			if not (key_name in last_result.keys()):
				last_result[key_name] = course[8]
				notify(course)
				flag_changed = True
	f_log.close()
	# save the dic as json if changed
	if flag_changed:
		with open('result.json', 'w') as f_json:
			json.dump(last_result, f_json)
	# else: print_log("No new result")
	

def print_log(*text):
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) ,*text)
    sys.stdout.flush()
    return


def notify(course):
	global token
	session = requests.Session()
	# if expired, get new token and save
	if time.time() >= token['time'] + token['expire']:
		print_log("Requireing new token...")
		t_url = "https://api.weixin.qq.com/cgi-bin/token"
		t_params = {
			'grant_type': 'client_credential',
			'appid': userinfo.appid,
			'secret': userinfo.appsecret
		}
		r = retry_get(2, session, t_url,  params=t_params)
		r_token = json.loads(r.text)
		token['token'] = r_token['access_token']
		token['time'] = time.time()
		token['expire'] = r_token['expires_in']
		print_log(token)
		with open('token.json', 'w') as f_json:
			json.dump(token, f_json)

	p_url = "https://api.weixin.qq.com/cgi-bin/message/template/send"
	p_params = {
		'access_token': token['token']
	}
	p_msg = {
		'touser': userinfo.wechatid,
		'template_id': userinfo.templeid,
		'url': 'http://bjut.devchen.cn/csx.php',
		'topcolor': '#3B74AC',
		'data': {
			'name': {
				'value': course[3],
				'color': '#173177'
			},
			'marks': {
				'value': course[8],
				'color': '#ff0000'
			},
			'credit': {
				'value': course[6],
				'color': '#173177'
			},
			'gpa': {
				'value': course[7].lstrip(),
				'color': '#173177'
			}
		}
	}
	p_data = json.dumps(p_msg)
	r = retry_post(3, session, p_url, params=p_params, data=p_data)
	print_log(course)
	print_log(r.text)



if __name__ == '__main__':
	load_last_result()
	s = login(userinfo.usr, userinfo.pwd)
	name = get_name(s, userinfo.usr)
	print_log(userinfo.usr, name)
	while 1:
		viewstate = get_viewstate(s, userinfo.usr, name)
		get_score(s, userinfo.usr, name, viewstate)
		time.sleep(60)