Field Protection & Selection in mongoose

## Purpose

To protect sensitive fields like:

- password hashes
- reset tokens
- API keys
- 2FA secrets

from being returned automatically in database queries.

# `select: false` <!--the default lock -->

I used:

```ts
select: false

I used select: false in my User model in the pssword field.
This ensures that if a call is made to return he User object it automatically leaves out the password field.

Example output
{
"name" : "Kate Mangena"
"email": "kate@gmail.com".
}
However some instances require the password field eg hashing and comparing the password ti see if it matches before giving user access to it. Thus we use .select("+password")

This is more like saying I know the field is secure by default from all db calls but i need to use it just for now

This reduces risks of

- accidental exposures in API responses
- logging sensitive data
- leaking credentials during debugging

note: the concept is just an application layer protection. Does not mean the data will dissapear, admn users with access to the db can also access it
```
