:orphan:
(avoid-race-conditions-with-our-easy-to-follow-strategies)=

# Avoid race conditions with our easy to follow strategies!

"Race conditions" are bugs that occur as a result of the timing or order in which multiple operations are executed. This is a fairly broad category of bugs that can manifest themselves in a variety of ways depending on the problem space. Unfortunately, race conditions are notoriously difficult to solve. Exclusive access or critical sections significantly slow down application performance. They obstruct the use of computer resources and destroy our CPU cache utilization.

We want to keep synchronization operations to a minimum, but we don't want undefined behavior. There are numerous optimizations and strategies available for developing high-performance multi-threaded applications. Maximizing read-only state, immutability, and so on is a great example of this. The real issue is recognizing that you have a race condition.

## Detecting a race condition

There are some excellent race detection tools available on the market. Some use static analysis to review application code and identify risky areas. Others work during runtime to monitor thread activity. They aren't as common because the debug environment isn't as close to the "real world."
The manufacturing environments are incredibly complex, and they are becoming more so by the day. Detecting and validating a race in that environment is difficult.

## TOCTOU

“Time-of-check to time-of-use” (TOCTOU) is a type of race condition that occurs when the state of a resource changes between checking its state and using the result. TOCTOU is typically discussed in the context of filesystem operations, but variations in many areas of the systems we build are possible.

Checking if a file is accessible and then reading it is a common example of a TOCTOU race condition. If the file is deleted or otherwise modified after the initial check, you will get an unhandled exception at best. At worst, you may be exposing a security vulnerability. Skip the access check and instead wrap the readFile in a try/catch to handle any errors.

## Atomicity

In the context of database systems, "atomic updating" is commonly used.

```
const user = db.users.findUser(id)

If (user.role == ‘admin’) {
  user.superPowers = true
  user.save()
}
```

In a simple example, the user is retrieved from the database, some logic is applied, and then a query to update the user is executed. However, this is a non-atomic operation, and there is no guarantee that the user's role in the database remains set to "admin" between the time of the check and the update. In this fictitious example, the result could be a security vulnerability in the application. However, depending on the complexity of the system, it could be even more difficult to detect in a real-world scenario.

Create an atomic update query instead, which performs the update in a single statement.

## Countermeasures

It is necessary to consider avoiding race conditions for not only what your code is doing, but also how other parts of the system will use your code. There are no silver bullets here, but here are some pointers to consider in addition to concurrent design:

- Update the database atomically. To craft your update query, do not rely on previously queried information about the record you are updating.

- Avoid sharing "global" state whenever possible, especially when dealing with concurrency. Consider the implications of concurrent access to data structures and how it affects the program's logic or the correctness of the data itself.

- If concurrent routines must share state, consider using a mutually exclusive or another locking mechanism to control access to the shared resource. This increases complexity, but it is sometimes unavoidable.

## Final Words

Race conditions can be a difficult problem to solve, but thankfully there are a few strategies that can help. Firstly, it is important to identify when a race condition might occur. Once you have identified potential race conditions, you can then take steps to avoid them. Finally, if you do encounter a race condition, there are a few strategies that can help you to solve the problem. With these strategies in mind, you should be able to avoid or solve race conditions with ease.

:::{seealso}
Looking to expand your knowledge of penetration testing? Check out our online course, [MPT - Certified Penetration Tester](https://www.mosse-institute.com/certifications/mpt-certified-penetration-tester.html) In this course, you'll learn about the different aspects of penetration testing and how to put them into practice.
:::
