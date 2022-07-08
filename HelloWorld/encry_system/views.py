from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from .models import DataInfo
from user_system.models import UserInfo
from django.http import HttpResponse, Http404, FileResponse
from django.utils.encoding import escape_uri_path
from django.contrib import messages

from SM import SM2, SM3, SM4, SM9

mk = (([10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634],
       [8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531], [1, 0]), (1, 2, 1), (
          962409270692906665210497985413989704088720419309240615841368990023997216812,
          3271581871419785851668579019734310847216340692063108518506367024373266193080,
          18304055564673556129558499187660942613405293183050823021561530679809577054750),
      [12864935809406530183584304405851160175667039392258496330691647811497774067966,
       7671855242883030625702626367573241181399904276705224870982398885438093219978,
       19892112364475781574564217588139883697418629755269037369977109364281686357441,
       11055964186984541202456906089170873840264815486362552431889020299866018819837,
       21026077087415008328773591346915115192124874979089066696296397179397458561250,
       19711074527443996329451729216430630520892171955136537951685764103141776985295,
       3417147333254890389950332865898426053600691534567759795846152213046589114775,
       12027133373727411513126348199328180361257751009808339923352908838272183974675,
       11754746869443985818342443022268864735769904962059524303661028661681260002184,
       21005887229246336758210326878113100826700178637445813813063758813503119548863,
       4765904765895042370241401283823761831087544913906074352223180329566547445076,
       9104519774161028272206245001373125648326128992926511600907081194312425859064])
master_public = SM9.get_master_public(mk)
master_secret = 724898525711316440692027036366274753928939329665328187567054993041654584178
sk = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
pk = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020" \
     "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"


# Create your views here.
def index(request):
    if request.method == 'GET':
        if request.session.get('username') and request.session.get('uid'):
            return render(request, 'encry/index.html')
        c_username = request.COOKIES.get('username')
        c_uid = request.COOKIES.get('uid')
        if c_username and c_uid:
            request.session['username'] = c_username
            request.session['uid'] = c_uid
            return render(request, 'encry/index.html')
        return HttpResponseRedirect('/user/login')


def encry(request):
    if request.method == 'GET':
        if request.session.get('username') and request.session.get('uid'):
            return render(request, 'encry/encry.html')
        c_username = request.COOKIES.get('username')
        c_uid = request.COOKIES.get('uid')
        if c_username and c_uid:
            request.session['username'] = c_username
            request.session['uid'] = c_uid
            return render(request, 'encry/encry.html')
        return HttpResponseRedirect('/user/login')

    elif request.method == "POST":
        File = request.FILES.get("myfile", None)
        if File is None:
            messages.error(request, '请选择上传文件')
            return HttpResponseRedirect('/encry/encry')
        else:
            choice = request.POST['encode_way']
            en_or_de = request.POST['en_or_de']
            sign_text = request.POST['sign']
            if en_or_de == '加密':
                plaintext = File.read().decode()
                name = File.name
                if choice == 'SM2':
                    uid = request.session['uid']
                    user = UserInfo.objects.get(id=uid)
                    if user:
                        public_key = user.public_key
                    else:
                        return HttpResponse("user error")
                    plaintext_h = SM3.sm3_hash(plaintext)
                    sign = SM9.sm9_sign(master_public, master_secret, sign_text, plaintext_h)
                    plaintext = plaintext + sign
                    print(plaintext)
                    ciphertext = SM2.sm2_encryt(plaintext, public_key)
                    name_h = SM3.sm3_hash(name)
                    ciphertext_h = SM3.sm3_hash(ciphertext)
                    DataInfo.objects.create(tittle_hash=name_h, plaintext_hash=plaintext_h,
                                            chipertext_hash=ciphertext_h,
                                            encode_ways=choice, user_id=uid)
                    file_name = 'en_' + File.name
                    with open('./tmp/' + file_name, 'w') as f:
                        if f:
                            f.write(ciphertext)
                        else:
                            messages.error(request, '未知错误，签名失败')
                            return HttpResponseRedirect('/encry/encry')
                elif choice == 'SM4':
                    # `encrypt_ecb`
                    uid = request.session['uid']
                    key = request.POST['key']
                    plaintext_h = SM3.sm3_hash(plaintext)
                    sign = SM9.sm9_sign(master_public, master_secret, sign_text, plaintext)
                    plaintext = plaintext + sign
                    print(plaintext)
                    ciphertext = SM4.sm4_encryt(key, plaintext)
                    name_h = SM3.sm3_hash(name)
                    ciphertext_h = SM3.sm3_hash(ciphertext)
                    DataInfo.objects.create(tittle_hash=name_h, plaintext_hash=plaintext_h,
                                            chipertext_hash=ciphertext_h,
                                            encode_ways=choice, user_id=uid)
                    file_name = 'en_' + File.name
                    with open('./tmp/' + file_name, 'w') as f:
                        if f:
                            f.write(ciphertext)
                        else:
                            messages.error(request, '未知错误，签名失败')
                            return HttpResponseRedirect('/encry/encry')

            elif en_or_de == '解密':
                ciphertext = File.read().decode()
                if choice == 'SM2':
                    uid = request.session['uid']
                    user = UserInfo.objects.get(id=uid)
                    if user:
                        private_key = user.private_key
                    else:
                        return HttpResponse("user error")
                    plaintext = SM2.sm2_decryt(ciphertext, private_key)
                    sign, plaintext = SM9.get_sign(plaintext)
                    plaintext_h = SM3.sm3_hash(plaintext)
                    print(sign)
                    verify = SM9.sm9_verify(master_public, sign_text, plaintext_h, sign)
                    if verify:
                        file_name = 'de_' + File.name
                        with open('./tmp/' + file_name, 'w') as f:
                            f.write(plaintext)
                    else:
                        messages.error(request, '消息发生改变，验签失败')
                        return HttpResponseRedirect('/encry/encry')
                elif choice == 'SM4':
                    key = request.POST['key']
                    plaintext = SM4.sm4_decryt(key, ciphertext)
                    sign, plaintext = SM9.get_sign(plaintext)
                    print(sign)
                    verify = SM9.sm9_verify(master_public, sign_text, plaintext, sign)
                    if verify:
                        file_name = 'de_' + File.name
                        with open('./tmp/' + file_name, 'w') as f:
                            f.write(plaintext)
                    else:
                        messages.error(request, '消息发生改变，验签失败')
                        return HttpResponseRedirect('/encry/encry')

            response = FileResponse(open('./tmp/' + file_name, 'rb'))
            response['content_type'] = "application/octet-stream"
            response['Content-Disposition'] = 'attachment; filename={}'.format(escape_uri_path(file_name))
            return response
