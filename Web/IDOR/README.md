# IDOR
## Identifying IDORs
- [ ] Check for URL parameters & APIs
- [ ] Check for AJAX calls
- [ ] Compare user roles
- [ ] Check for encoded references
- **AJAX Calls**
    - The following example shows a basic example of an AJAX call:
    ```javascript
    function changeUserPassword() {
    $.ajax({
            url:"change_password.php",
            type: "post",
            dataType: "json",
            data: {uid: user.uid, password: user.password, is_admin: is_admin},
            success:function(result){
                //
            }
        });
    }
    ```



