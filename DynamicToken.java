package GoogleAuthenticator;

import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
/**
 * 谷歌动态令牌
 * @author Mr.Chen
 *
 */
public class DynamicToken {
	/**
	 * 摘要对象
	 */
	private Mac mac;
	/**
	 * 秘钥
	 */
	private String secKey;
	/**
	 * 与系统的时间间隔
	 */
	private int invertal;
	/**
	 * 构造函数
	 * @param key
	 */
	public DynamicToken(String key) {
		this.secKey = key;
		 try {
			mac= Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 获取 动态口令
	 * @throws Exception 
	 */
	public String getDynamicCode(String key,long systemTime,int invertal) throws Exception{
		byte[] data;
		data = sha1(key,(systemTime+invertal)/30000);//sha1生成 20字节（160位）的数据摘要
		int o = data[19]& 0xf;//通过对最后一个字节的低4位二进制位建立索引，索引范围为  （0-15）+4  ，正好20个字节。
		int number = hashToInt(data, o)& 0x7fffffff;  //然后计算索引指向的连续4字节空间生成int整型数据。
		return output(number%1000000);//对获取到的整型数据进行模运算，再对结果进行补全（长度不够6位，在首位补零）得到长度为6的字符串
	}
	/**
	 * 获取 动态口令
	 * @throws Exception 
	 */
	public String getDynamicCode(String key,long systemTime) throws Exception{
		return getDynamicCode(key, systemTime, invertal);
	}
	/**
	 * 获取 动态口令
	 * @throws Exception 
	 */
	public String getDynamicCode(String key) throws Exception{
		return getDynamicCode(key, System.currentTimeMillis(), invertal);
	}
	/**
	 * 获取 动态口令
	 * @throws Exception 
	 */
	public String getDynamicCode() throws Exception{
		return getDynamicCode(secKey, System.currentTimeMillis(), invertal);
	}
	/**
	 * 设置时间偏移量  单位：毫秒
	 * @return 
	 */
   public DynamicToken setTimeIntertal(int offset){
	   this.invertal = offset;
	   return this;
   }
	/**
	 * 取数据摘要
	 * @param secret
	 * @param msg
	 * @return 加密后的字节数字
	 * @throws Exception
	 */
	private byte[] sha1(String secret,long msg) throws Exception{
		SecretKey secretKey = new SecretKeySpec(Base32String.decode(secret), "");//创建秘钥
		mac.reset();
		mac.init(secretKey);//初始化秘钥
		byte[] value = ByteBuffer.allocate(8).putLong(msg).array();//将long类型的数据转换为byte数组
		return mac.doFinal(value);//计算数据摘要
	}
    /**
     * 将byte数组转化为整数
     * @param bytes
     * @param start
     * @return int
     */
    private int hashToInt(byte[] bytes, int start) {
        DataInput input = new DataInputStream(
            new ByteArrayInputStream(bytes, start, bytes.length - start));
        int val;
        try {
          val = input.readInt();
        } catch (IOException e) {
          throw new IllegalStateException(e);
        }
        return val;
      }
    /**
     * 格式化输出结果
     * @param intCode
     */
    private String output(int x){
    	String s = String.valueOf(x);
    	for (int i = 0; i <6-s.length(); i++) {
			s="0"+s;
		}
    	return s;
    }
}
