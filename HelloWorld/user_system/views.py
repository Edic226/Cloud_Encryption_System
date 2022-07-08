from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import messages
from SM import SM3, SM2
from .models import UserInfo


# Create your views here.
def login(request):
    if request.method == 'GET':
        if request.session.get('username') and request.session.get('uid'):
            return HttpResponseRedirect('/encry/index')
        c_username = request.COOKIES.get('username')
        c_uid = request.COOKIES.get('uid')
        if c_username and c_uid:
            request.session['username'] = c_username
            request.session['uid'] = c_uid
            return HttpResponseRedirect('/encry/index')
        return render(request, 'user/login.html')

    elif request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if username == '' and password == '':
            messages.error(request, '用户名和密码不能为空')
            return HttpResponseRedirect('/user/login')
        try:
            user = UserInfo.objects.get(username=username)
        except Exception as e:
            print('--login user error %s' % (e))
            messages.error(request, '您的用户名或密码有误，请重新输入')
            return HttpResponseRedirect('/user/login')
        prepassword = SM3.sm3_hash(password)

        if prepassword != user.password:
            messages.error(request, '您的用户名或密码有误，请重新输入')
            return HttpResponseRedirect('/user/login')
        #  记录会话数据
        request.session['username'] = username
        request.session['uid'] = user.id
        resp = HttpResponseRedirect('/encry/index')

        # 判断用户是否点选‘记住用户名’
        if 'remember' in request.POST:
            resp.set_cookie('username', username, 3600 * 24 * 3)
            resp.set_cookie('uid', user.id, 3600 * 24 * 3)  # 点击存储时间三天
        return resp


def register(request):
    if request.method == 'GET':
        return render(request, 'user/register.html')
    elif request.method == 'POST':
        username = request.POST['username']
        password_1 = request.POST['password_1']
        password_2 = request.POST['password_2']
        if username == '' and password_1 == '':
            messages.error(request, '用户名和密码不能为空')
            return HttpResponseRedirect('/user/register')
        if password_2 == '':
            messages.error(request, '请再次输入密码')
            return HttpResponseRedirect('/user/login')
        if password_1 != password_2:
            messages.error(request, '两次密码输入不一致')
            return HttpResponseRedirect('/user/register')
        # sm3加密密码信息
        password_m = SM3.sm3_hash(password_1)
        old_user = UserInfo.objects.filter(username=username)
        if old_user:
            messages.error(request, "用户名已经被注册")
            return HttpResponseRedirect('/user/register')
        # 有可能重复插入报错，并发写入问题
        sk, pk = SM2.sm2_getkey()
        try:
            user = UserInfo.objects.create(username=username, password=password_m, private_key=sk, public_key=pk)
        except Exception as e:
            print('--create user error %s' % e)
            messages.error(request, "用户名已经被注册")
            return HttpResponseRedirect('/user/register')
        messages.error(request, '注册成功')
        return HttpResponseRedirect('/user/login')


def logout(request):
    if 'username' in request.session:
        del request.session['username']
    if 'uid' in request.session:
        del request.session['uid']
    resp = HttpResponseRedirect('/')
    if 'username' in request.COOKIES:
        resp.delete_cookie('username')
    if 'uid' in request.COOKIES:
        resp.delete_cookie('uid')
    messages.error(request, '成功退出')
    return resp


def ret(request):
    return HttpResponseRedirect('/')
