<h1>flashMap - Spring MVC 重定向参数传递</h1>

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [1. 背景](#1-背景)
  - [2. `flashMap`](#2-flashmap)
- [3. 源码分析](#3-源码分析)

<!-- /code_chunk_output -->

# 1. 背景

说到 Web 请求参数传递, 大家能想到哪些参数传递方式?

参数可以放在地址栏中, 不过地址栏参数的长度有限制, 并且在有的场景下我们可能不希望参数暴漏在地址栏中. 参数可以放在请求体中, 这个没啥好说的.

小伙伴们试想这样一个场景:

在一个电商项目中, 有一个提交订单的请求, 这个请求是一个 POST 请求, 请求参数都在请求体中. 当用户提交成功后, 为了防止用户刷新浏览器页面造成订单请求重复提交, 我们一般会将用户重定向到一个显示订单的页面, 这样即使用户刷新页面, 也不会造成订单请求重复提交.

大概的代码就像下面这样:

```java
@Controller
public class OrderController {
    @PostMapping("/order")
    public String order(OrderInfo orderInfo) {
        //其他处理逻辑
        return "redirect:/orderlist";
    }
}
```

但是这里有一个问题: 如果我想传递参数怎么办?

如果是服务器端跳转, 我们可以将参数放在 request 对象中, 跳转完成后还能拿到参数, 但是如果是客户端跳转我们就只能将参数放在地址栏中了, 像上面这个方法的返回值我们可以写成: `return "redirect:/orderlist?xxx=xxx";`, 这种传参方式有两个缺陷:

- 地址栏的长度是有限的, 也就意味着能够放在地址栏中的参数是有限的.
- 不想将一些特殊的参数放在地址栏中.

那该怎么办? 还有办法传递参数吗?

这就是今天要和大家介绍的 `flashMap`, 专门用来解决重定向时参数的传递问题.

## 2. `flashMap`

在重定向时, 如果需要传递参数, 但是又不想放在地址栏中, 我们就可以通过 `flashMap` 来传递参数, 先来一个简单的例子大家看看效果.

首先我们定义一个简单的页面, 里边就一个 post 请求提交按钮, 如下:

```xml
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<form action="/order">
    <input type="submit" value="提交">
</form>
</body>
</html>
```

然后在服务端接收该请求, 并完成重定向:

```js
@Controller
public class OrderController {
    @PostMapping("/order")
    public String order(HttpServletRequest req) {
        FlashMap flashMap = (FlashMap) req.getAttribute(DispatcherServlet.OUTPUT_FLASH_MAP_ATTRIBUTE);
        flashMap.put("name", "江南一点雨");
        return "redirect:/orderlist";
    }

    @GetMapping("/orderlist")
    @ResponseBody
    public String orderList(Model model) {
        return (String) model.getAttribute("name");
    }
}
```

首先在 `order` 接口中, 获取到 `flashMap` 属性, 然后存入需要传递的参数, 这些参数最终会被 SpringMVC 自动放入重定向接口的 `Model` 中, 这样我们在 `orderlist` 接口中, 就可以获取到该属性了.

当然, 这是一个比较粗糙的写法, 我们还可以通过 `RedirectAttributes` 来简化这一步骤:

```js
@Controller
public class OrderController {
    @PostMapping("/order")
    public String order(RedirectAttributes attr) {
        attr.addFlashAttribute("site", "www.javaboy.org");
        attr.addAttribute("name", "微信公众号：江南一点雨");
        return "redirect:/orderlist";
    }

    @GetMapping("/orderlist")
    @ResponseBody
    public String orderList(Model model) {
        return (String) model.getAttribute("site");
    }
}
```

`RedirectAttributes` 中有两种添加参数的方式:

- `addFlashAttribute`: 将参数放到 `flashMap` 中.
- `addAttribute`: 将参数放到 URL 地址中.

经过前面的讲解, 现在小伙伴们应该大致明白了 `flashMap` 的作用了, 就是在你进行重定向的时候, 不通过地址栏传递参数.

很多小伙伴可能会有疑问, 重定向其实就是浏览器发起了一个新的请求, 这新的请求怎么就获取到上一个请求保存的参数呢? 这我们就要来看看 SpringMVC 的源码了.

# 3. 源码分析

首先这里涉及到一个关键类叫做 `FlashMapManager`, 如下:

```js
public interface FlashMapManager {
 @Nullable
 FlashMap retrieveAndUpdate(HttpServletRequest request, HttpServletResponse response);
 void saveOutputFlashMap(FlashMap flashMap, HttpServletRequest request, HttpServletResponse response);
}
```

两个方法含义一眼就能看出来:

- `retrieveAndUpdate`: 这个方法用来恢复参数, 并将恢复过的的参数和超时的参数从保存介质中删除.
- `saveOutputFlashMap`: 将参数保存保存起来.

FlashMapManager 的实现类如下: