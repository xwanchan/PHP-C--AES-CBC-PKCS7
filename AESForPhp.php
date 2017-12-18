<?php 
$privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
EOD;
$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----
EOD;
$keyStr = '3738597658384d6c316a4758527a5a35';
$iv = '00000000000000000000000000000000';

/* AES CBC Pkcs7 encrypt */
$data = array(
    'sn' => '98261712365456',
    'outTransId' => '10060',
    'orderTitle' => '',
    'amount' => '0.01',
    'payTypeId' => '1001',
    'reamrk' => '',
    'notifyUrl' => '',
);
$plainText = json_encode($data);
$content = aes128cbcEncrypt($plainText, $iv, $keyStr);
$data = array(
    'devId'     => 'xqHQzM5n',
    'content'   => $content,
    'signature' => signData($privateKey, $content),
);
$url = 'https://...';
$result = postData($url, $data);
echo '加密加签'.'<br />';
echo '请求的字符串:'.'<br />'.$plainText.'<br />';
echo '请求的地址:'.'<br />'.$url.'<br />';
echo '加密的字符串以及签名:'.'<br />';
echo '<pre>';print_r(json_encode($data));echo '</pre>';
echo '返回的结果:'.'<br />';
echo '<pre>';print_r($result);echo '</pre>';

/* AES CBC Pkcs7 decrypt */
$string = '{"content": "", "signature": ""}';
$content = '';
$sign = '';
$returnV = verifySign($publicKey, $content, $sign);
$return = aes128cbcDecrypt($content, $keyStr, $iv);
echo '验签解密'.'<br />';
echo '请求的字符串:'.'<br />'.$string.'<br />';
echo '请求的地址:'.'<br />'.'https://...'.'<br />';
echo '验签后的结果:'.'<br />'.$returnV.'<br />';
echo '解密后的结果:'.'<br />'.$return.'<br />';

function postData($url, $data) {
    $data_string = json_encode($data);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,0);
    curl_setopt($ch, CURLOPT_HEADER,0);
    curl_setopt($ch, CURLOPT_POST,1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);

    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function addPkcs7Padding($string, $blocksize = 16) {
    $len = strlen($string);
    $pad = $blocksize - ($len % $blocksize);
    $string .= str_repeat(chr($pad), $pad);
    return $string;
}
function aes128cbcEncrypt($string, $iv, $key) {  
    return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, hex2bin($key), addPkcs7Padding($string) , MCRYPT_MODE_CBC, hex2bin($iv)));
}

function stripPkcs7Padding($text) { 
    $pad = ord($text{strlen($text) - 1});  
    if ($pad > strlen($text)) return false;  
    if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;  
    return substr($text, 0, -1 * $pad); 
} 
function aes128cbcDecrypt($string, $key, $iv) {
    return stripPkcs7Padding(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, hex2bin($key), base64_decode($string), MCRYPT_MODE_CBC, hex2bin($iv)));
}  

function signData($privateKey, $data) {
    $binary_signature = "";
    $algo = "SHA256";
    openssl_sign(base64_decode($data), $binary_signature, $privateKey, $algo);
    return base64_encode($binary_signature);
}

function verifySign($publicKey, $content, $sign) {
    return (bool)openssl_verify(base64_decode($content), base64_decode($sign), $publicKey, 'SHA256');
}
