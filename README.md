# login-blog-relation
user login and post blogs

This project creates a website, where the user can register an account and post blogs on the website.

Blogs:
There is a Front page that lists blog posts.
A form to submit new blog.
Blog posts have their own page.

Registration:
The website has a registration form that validates user input, and displays the error(s) when necessary.
After a successful registration, a user is directed to a welcome page with a greeting, “Welcome, ” where is a name set in a cookie.
If a user attempts to visit the welcome page without being signed in (without having a cookie), then redirect to the Signup page.

Login:
The website has a login form that validates user input, and displays the error(s) when necessary.
After a successful login, the user is directed to the same welcome page.

Logout：
The user can logout by clicking the "logout" at the top right corner of the page.
After logging out, the cookie is cleared and user is redirected to the Signup page.

user authorization:
A user can only post, edit delete or comment a blog when logged in.
A user cannot edit or delete other users' blogs.
A user can edit and delete his own comment.
A user can like a blog, but cannot like his own blogs. User can like a blog only once.
A user can cancel his like to a blog post.

Environment:
The website is developed in Windows environment and deployed by Google App Engine.

Running at Google App Engine Launcher:
To run this code, open the "Google App Engine Launcher", click "File" at the top left and select "Add Existing Application",
then choose the project folder path in the "Application Path".
The project will be shown at Google App Engine Launcher interface. Choose this projec and click "Run", then the project will run.
Open you browser and type "localhost:(port)", you will see the website.

The application is deployed at http://login-blog-relation.appspot.com. http://login-blog-relation.appspot.com/blog list all the
blogs.

