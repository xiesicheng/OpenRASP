package com.dubbo.provider.serviceImpl;


import com.dubbo.demo_interface.api.IUserService;
import org.springframework.stereotype.Service;
import java.sql.*;

/**
 * Created by anyang on 2018/6/25.
 */
@Service
public class UserService implements IUserService {


    public String select() {
        try {
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection("jdbc:mysql://127.0.0.1/mysql", "root", "");
            Statement stmt = conn.createStatement();
            ResultSet rset = stmt.executeQuery ("SELECT * FROM user");
            System.out.println("1111111111111111111");
            StringBuilder sb = new StringBuilder();
            if (!rset.next()) {
                sb.append("<P> No matching rows.<P>\n");
            } else {
                do {
                    sb.append(rset.getInt(1)+"===");
                    sb.append(rset.getString(2) + "\n");
                } while (rset.next());
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
