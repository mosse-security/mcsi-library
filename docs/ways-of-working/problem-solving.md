# Problem Solving

```{admonition} Must Understand
:class: warning
Problem solving is the most important skill to advance you technical cybersecurity competencies! You are only as good as the problems you can solve. Take this advice very seriously and become a master problem solver.
```

Problem solving in cybersecurity requires a combination of technical and non-technical skills. On the technical side, problem solvers must be able to understand and work with complex systems. They must also have a good understanding of security threats and how to defend against them. On the non-technical side, problem solvers must be able to communicate effectively with others and work well in team settings.

The ability to solve problems is critical to the success of any cybersecurity professional.

In this section, we offer some problem solving and structured analytics techniques you are encouraged to learn and master.

## Problem Solving Techniques

Problem solving is the process of identifying and resolving issues or obstacles that are preventing the attainment of a desired goal. In many cases, problem solving involves overcoming challenges or obstacles that are blocking the path to the goal, but it can also involve finding new and creative solutions to seemingly insurmountable problems. There are a variety of different approaches that can be taken when problem solving, and the most effective approach will vary depending on the specific problem that needs to be resolved. In some cases, a simple trial-and-error approach may be all that is needed to find a solution. However, for more complex problems, a more systematic approach may be necessary.

### Simple Techniques

Here's a list of techniques that can help with problem solving:

- Look for a pattern
- Break the problem into different parts
- Make a table
- Make a diagram
- Make an equation
- Work backwards
- Develop tests that will only work once the solution is reached
- Solve a simpler problem before coming back to this one

### Algorithmic Thinking

This involves creating a step-by-step process or set of rules to follow in order to solve a problem. It's especially useful in programming and data processing tasks.

**Simple Example:**

Imagine that you are tasked with cataloging all devices and software on a network, you could create a step-by-step process:

1. Decide which devices and software to include
2. Choose network scanning and inventory tools
3. Set up tools for network scanning
4. Perform a scan on test machines and confirm everything worked as expected
5. Break down the scans in blocks of 500 machines at a time
6. Review scan results for devices and software.
7. Verify scan accuracy manually
8. Organize and record findings in a database/spreadsheet
9. Automate scanning and validating results

### Divide and Conquer

This technique involves breaking down a large problem into smaller, more manageable parts, solving each part individually, and then combining them to solve the overall issue.

The following coding guidelines can be used to apply this technique in software engineering:

1. **Limit Function Size:** Aim to keep functions concise, ideally not exceeding 100 lines of code. This enhances readability and makes functions easier to understand and maintain.

2. **Single Responsibility Principle:** Each function should perform a single task or responsibility. Avoid creating functions that handle multiple unrelated tasks.

3. **Meaningful Names for Functions and Variables:** Choose descriptive and meaningful names that clearly indicate the purpose of the function or the role of the variable.

4. **Consistent Coding Style:** Adhere to a consistent coding style, including indentation, naming conventions, and file structure. This makes the codebase easier to navigate and maintain.

5. **Use Comments Sparingly and Effectively:** Write comments to explain the 'why' behind complex logic, not the 'how'. Avoid redundant comments for straightforward code segments.

6. **Code Refactoring:** Regularly refactor code to improve efficiency and readability. This includes simplifying complex functions, removing redundant code, and optimizing algorithms.

7. **Avoid Deep Nesting:** Limit the depth of nesting (if/else, loops, etc.) within functions. Deeply nested code can be difficult to read and understand.

8. **Limit Parameter Count:** Aim to keep the number of parameters for a function to a minimum. If a function requires many parameters, consider using an object to encapsulate them.

### Simulation and Modeling

Creating a virtual model of a system to test different scenarios and solutions. This is often used to predict the effects of changes in complex systems.

**Simple Example:**

Examples of unit tests created by MCSI to verify the requirements of each exercise are displayed in the accompanying image. We are able to keep track of almost 2,500 exercises thanks to these little checks, which also ensure that the proper file format and structure are followed.

```{thumbnail} ../images/ways-of-working/unit-tests-example.png
:class: block max-width-500 mb-4 mt-4 mx-auto
```

It helps to write software with a "test-driven" approach. In order to ensure that your software passes all unit tests, you must first write them. Subsequently, you gradually compose the function code required to pass your tests. You make small changes to the tests if you discover along the way that the functions do not follow the specifications you initially imagined. In this manner, you can verify that the entire body of your code operates as intended and be certain that every function you create operates as expected.

### Root Cause Analysis

RCA is a method of problem solving that tries to identify the root causes of faults or problems. It's a systematic process often used for fixing complex software issues.

<img alt="RCA Process" class="grey-border mb-3" src="/images/problem-solving/rca-process.svg">

MCSI offers a detailed RCA method [here](rca-method).

### Debugging

This involves identifying, isolating, and fixing bugs in software. It typically includes going through code, using debuggers, or adding print statements to track down where the problem occurs.

1. **Set Up for Debugging:** Make sure you have the right tools and a safe place to test your code without causing more issues.

2. **Use a Debugger:** Use a debugging tool to find out where in your code the problem is happening. Set breakpoints to pause the code at certain points.

3. **Find the Specific Issue:** Narrow down where in your code the bug is. You can comment out parts of the code to see if the problem still happens.

4. **Watch Your Code Run:** Step through your code line by line with the debugger to see where things go wrong.

5. **Check Variables and Logs:** Use print statements to see what your variables are at different points. Look at any log files your program might have for clues.

6. **Try Fixes and See What Happens:** Based on what you find, make some changes and see if they fix the problem.

7. **Implement Unit Tests Post-Fix:** Once the issue is identified and fixed, write unit tests to validate the fix and ensure it works as intended. These tests should not only confirm that the specific problem is resolved but also check for potential side effects to prevent related issues in the future.

### The Pólya Method

George Pólya was a mathematician who proposed a general approach to problem solving that can be applied to software and cybersecurity problems.

**Step 1: Understand the problem**

In order to solve a problem, it is first necessary to understand what the problem is. This may seem obvious, but it is often overlooked. All too often, people try to solve a problem without first taking the time to fully understand it. This can lead to a lot of wasted effort and frustration. A good way to start understanding a problem is to ask some questions about it.

- Do you understand all the terminology and parts of the problem?
- What are we trying to achieve?
- What are the data? e.g. error messages, input values etc.
- What is the unknown?
- Are there any assumptions?
- Do you have enough information to solve the problem?

Asking these kinds of questions can help to clarify the problem and make it easier to solve.

In order to understand the problem, it is important to consider all of the factors that may be involved. This includes looking at the situation from multiple perspectives and gathering as much information as possible. Once you have a good understanding of the problem, you can start to develop a plan to solve it. Keep in mind that there may be multiple ways to solve the problem, so it is important to explore all of the options and choose the one that is best suited for the situation.

```{admonition} Tip!
:class: hint

Drawing figures and diagrams is usually helpful when trying to solve hard problems.
```

**Step 2: Devise a plan**

There are many ways to devise a plan to solve a problem. One way is to brainstorm a list of possible solutions and then evaluate each one to see which is the best. Another way is to look at the problem from different perspectives and try to find a creative solution. Sometimes it helps to talk to others about the problem and get their input. Once a plan is devised, it is important to put it into action and see if it works. If not, it may be necessary to adjust the plan or come up with a new one.

- Understand the goal
- Look at other problems for inspiration (i.e., do you know a related problem?)
- Choose a smaller part to try

```{admonition} Tip!
:class: hint

Ask yourself "What is the simplest, quickest, safest, cheapest, easiest and surest way to try solve the problem?". Too often, people come up with over complicated plans and ideas!
```

**Step 3: Carry out the plan**

There are many different ways to carry out a plan to solve a problem. The most important thing is to make sure that the plan is comprehensive and well thought out. Every step of the plan should be carefully considered, and each potential obstacle should be taken into account. The plan should be designed to solve the problem in the most efficient and effective way possible.

- Focus on one part at a time
- Regularly check with the goal
- If something isn't working, use that information to learn more about the problem, then try something else

**Step 4: Look back**

When we look back after having solved a problem, we can see how far we've come and how much we've learned. We can also see what we could have done differently, and how we can improve in the future. This hindsight is valuable, and can help us to become better problem-solvers.

- Be clear that you reached the goal
- Find something you can learn