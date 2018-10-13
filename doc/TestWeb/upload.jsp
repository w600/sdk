<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>  
    <head>  
        <title>Upload a file please</title>  
    </head>  
    <body>  
        <h1>Please upload a file</h1>  
<!--   enctype(编码格式)必须为multipart/form-data  -->  
        <form method="post" action="<%=request.getContextPath()%>/upload.do" enctype="multipart/form-data">  
            <input type="text" name="name"/>  
            <input type="file" name="file"/>  
            <input type="submit"/>  
        </form>  
    </body>  
</html>  