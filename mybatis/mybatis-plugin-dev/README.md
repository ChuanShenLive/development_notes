<h1>MyBatis 插件开发</h1>

[地址](https://mp.weixin.qq.com/s/qcVSVeKIQA4RD4vlrzut7w)

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [1.MyBatis 插件接口](#1mybatis-插件接口)
- [2. MyBatis 拦截器签名](#2-mybatis-拦截器签名)
- [3. 被拦截的对象](#3-被拦截的对象)
  - [3.1 `org.apache.ibatis.executor.Executor`](#31-orgapacheibatisexecutorexecutor)
  - [3.2 `org.apache.ibatis.executor.parameter.ParameterHandler`](#32-orgapacheibatisexecutorparameterparameterhandler)
  - [3.3 `org.apache.ibatis.executor.resultset.ResultSetHandler`](#33-orgapacheibatisexecutorresultsetresultsethandler)
  - [3.4 `org.apache.ibatis.executor.statement.StatementHandler`](#34-orgapacheibatisexecutorstatementstatementhandler)
- [4. 开发分页插件](#4-开发分页插件)
  - [4.1 内存分页](#41-内存分页)
  - [4.2 自定义分页插件](#42-自定义分页插件)
    - [4.2.1 `PageRowBounds` 参数类型](#421-pagerowbounds-参数类型)
    - [4.2.2 `PageInterceptor` 拦截器](#422-pageinterceptor-拦截器)
- [5. 测试](#5-测试)

<!-- /code_chunk_output -->

在日常开发中, 小伙伴们多多少少都有用过 MyBatis 插件! 不知道小伙伴们有没有想过有一天自己也来开发一个 MyBatis 插件?
其实自己动手撸一个 MyBatis 插件并不难, 今天松哥就把手带大家撸一个 MyBatis 插件!

# 1.MyBatis 插件接口

即使你没开发过 MyBatis 插件, 估计也能猜出来, MyBatis 插件是通过拦截器来起作用的, MyBatis 框架在设计的时候, 就已经为插件的开发预留了相关接口, 如下: 

```java
public interface Intercepter {

    Object intercept(Invocation invocation) throws Throwable;
    
    default Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    default void setProperties(Properties properties) {
        // NOP
    }
}
```

这个接口中就三个方法, 第一个方法必须实现, 后面两个方法都是可选的. 三个方法作用分别如下:

1. `intercept`: 这个就是具体的拦截方法, 我们自定义 MyBatis 插件时, 一般都需要重写该方法, 我们插件所完成的工作也都是在该方法中完成的.

2. `plugin`: 这个方法的参数 target 就是拦截器要拦截的对象, 一般来说我们不需要重写该方法. `Plugin.warp` 方法会自动判断拦截器的签名和被拦截对象的接口是否匹配, 如果匹配, 参会通过动态代理拦截目标对象.

3. `setProperties`: 这个方法用来传递插件的参数, 可以通过参数来改变插件的行为. 我们定义好插件之后, 需要对插件进行配置, 在配置的时候, 可以给插件设置相关属性, 设置的属性可以通过该方法获取到. 插件属性设置像下面这样：

```xml
<plugins>
    <plugin interceptor="org.javaboy.mybatis03.plugin.CamelInterceptor">
        <property name="xxx" value="xxx"/>
    </plugin>
</plugins>
```

# 2. MyBatis 拦截器签名

拦截器定义好了后, 拦截谁? 这个就需要拦截器签名来完成了!

拦截器签名是一个名为 `@Intercepts` 的注解, 该注解中可以通过 `@Signature` 配置多个签名. `@Signature` 注解中则包含三个属性:

- `type`: 拦截器需要拦截的接口, 有 4 个可选项, 分别是: `Executor`, `ParameterHandler`, `ResultSetHandler` 以及 `StatementHandler`.
- `method`: 拦截器所拦截接口中的方法名, 也就是前面四个接口中的方法名, 接口和方法要对应上.
- `args`: 拦截器所拦截方法的参数类型, 通过方法名和参数类型可以锁定唯一一个方法.

一个简单的签名可能像下面这样:

```java
@Intercepts(@Signature(
        type = ResultSetHandler.class,
        method = "handleResultSets",
        args = {Statement.class}
))
public class CamelInterceptor implements Interceptor {
    //...
}
```

# 3. 被拦截的对象

根据前面的介绍, 被拦截的对象主要有如下四个:

## 3.1 `org.apache.ibatis.executor.Executor`

```java
public interface Executor {

  ResultHandler NO_RESULT_HANDLER = null;

  int update(MappedStatement ms, Object parameter) throws SQLException;

  <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler, CacheKey cacheKey, BoundSql boundSql) throws SQLException;

  <E> List<E> query(MappedStatement ms, Object parameter, RowBounds rowBounds, ResultHandler resultHandler) throws SQLException;

  <E> Cursor<E> queryCursor(MappedStatement ms, Object parameter, RowBounds rowBounds) throws SQLException;

  List<BatchResult> flushStatements() throws SQLException;

  void commit(boolean required) throws SQLException;

  void rollback(boolean required) throws SQLException;

  CacheKey createCacheKey(MappedStatement ms, Object parameterObject, RowBounds rowBounds, BoundSql boundSql);

  boolean isCached(MappedStatement ms, CacheKey key);

  void clearLocalCache();

  void deferLoad(MappedStatement ms, MetaObject resultObject, String property, CacheKey key, Class<?> targetType);

  Transaction getTransaction();

  void close(boolean forceRollback);

  boolean isClosed();

  void setExecutorWrapper(Executor executor);

}
```

各方法含义分别如下:

- `update`: 该方法会在所有的 `INSERT`, `UPDATE`, `DELETE` 执行时被调用, 如果想要拦截这些操作, 可以通过该方法实现.
- `query`: 该方法会在 `SELECT` 查询方法执行时被调用, 方法参数携带了很多有用的信息, 如果需要获取, 可以通过该方法实现.
- `queryCursor`: 当 `SELECT` 的返回类型是 `Cursor` 时, 该方法会被调用.
- `flushStatements`: 当 `SqlSession` 方法调用 `flushStatements` 方法 或 执行的接口方法中带有 `@Flush` 注解时该方法会被触发.
- `commit`: 当 `SqlSession` 方法调用 `commit` 方法时该方法会被触发.
- `rollback`: 当 `SqlSession` 方法调用 `rollback` 方法时该方法会被触发.
- `getTransaction`: 当 `SqlSession` 方法获取数据库连接时该方法会被触发.
- `close`: 该方法在懒加载获取新的 `Executor` 后会被触发.
- `isClosed`: 该方法在懒加载执行查询前会被触发.

---

## 3.2 `org.apache.ibatis.executor.parameter.ParameterHandler`

```java
public interface ParameterHandler {

  Object getParameterObject();

  void setParameters(PreparedStatement ps) throws SQLException;

}
```

各方法含义分别如下:

- `getParameterObject`: 在执行存储过程处理出参的时候该方法会被触发.
- `setParameters`: 设置 SQL 参数时该方法会被触发.

---

## 3.3 `org.apache.ibatis.executor.resultset.ResultSetHandler`

```java
public interface ResultSetHandler {

  <E> List<E> handleResultSets(Statement stmt) throws SQLException;

  <E> Cursor<E> handleCursorResultSets(Statement stmt) throws SQLException;

  void handleOutputParameters(CallableStatement cs) throws SQLException;

}
```

各方法含义分别如下:

- `handleResultSets`: 该方法会在所有的查询方法中被触发(除去返回值类型为 `Cursor` 的查询方法), 一般来说, 如果我们想对查询结果进行二次处理, 可以通过拦截该方法实现.
- `handleCursorResultSets`: 当查询方法的返回值类型为 `Cursor` 时, 该方法会被触发.
- `handleOutputParameters`: 使用存储过程处理出参的时候该方法会被调用.

## 3.4 `org.apache.ibatis.executor.statement.StatementHandler`

```java
public interface StatementHandler {

  Statement prepare(Connection connection, Integer transactionTimeout)
      throws SQLException;

  void parameterize(Statement statement)
      throws SQLException;

  void batch(Statement statement)
      throws SQLException;

  int update(Statement statement)
      throws SQLException;

  <E> List<E> query(Statement statement, ResultHandler resultHandler)
      throws SQLException;

  <E> Cursor<E> queryCursor(Statement statement)
      throws SQLException;

  BoundSql getBoundSql();

  ParameterHandler getParameterHandler();

}
```

各方法含义分别如下:

- `prepare`: 该方法在数据库执行前被触发.
- `parameterize`: 该方法在 `prepare` 方法之后执行, 用来处理参数信息.
- `batch`: 如果 MyBatis 的全剧配置中配置了 `defaultExecutorType="BATCH"`, 执行数据操作时该方法会被调用.
- `update`: 更新操作时该方法会被触发.
- `query`: 该方法在 `SELECT` 方法执行时会被触发.
- `queryCursor`: 该方法在 `SELECT` 方法执行时, 并且返回值为 `Cursor` 时会被触发.

在开发一个具体的插件时, 我们应当根据自己的需求来决定到底拦截哪个方法.

# 4. 开发分页插件

## 4.1 内存分页

MyBatis 中提供了一个不太好用的内存分页功能, 就是一次性把所有数据都查询出来, 然后在内存中进行分页处理, 这种分页方式效率很低, 基本上没啥用, 但是如果我们想要自定义分页插件, 就需要对这种分页方式有一个简单了解.

内存分页的使用方式如下, 首先在 `Mapper` 中添加 `RowBounds` 参数, 如下:

```js
public interface UserMapper {
    List<User> getAllUsersByPage(RowBounds rowBounds);
}
```

然后在 XML 文件中定义相关 SQL:

```xml
<select id="getAllUsersByPage" resultType="org.javaboy.mybatis03.model.User">
    select * from user
</select>
```

可以看到, 在 SQL 定义时, 压根不用管分页的事情, MyBatis 会查询到所有的数据, 然后在内存中进行分页处理.

`Mapper` 中方法的调用方式如下:

```java
@Test
public void test3() {
    UserMapper userMapper = sqlSessionFactory.openSession().getMapper(UserMapper.class);
    RowBounds rowBounds = new RowBounds(1,2);
    List<User> list = userMapper.getAllUsersByPage(rowBounds);
    for (User user : list) {
        System.out.println("user = " + user);
    }
}
```

构建 `RowBounds` 时传入两个参数, 分别是 `offset` 和 `limit`, 对应分页 SQL 中的两个参数. 也可以通过 `RowBounds.DEFAULT` 的方式构建一个 `RowBounds` 实例, 这种方式构建出来的 `RowBounds` 实例, `offset` 为 `0`, `limit` 则为 `Integer.MAX_VALUE`, 也就相当于不分页.

这就是 MyBatis 中提供的一个很不实用的内存分页功能.

了解了 MyBatis 自带的内存分页之后, 接下来我们就可以来看看如何自定义分页插件了.

## 4.2 自定义分页插件

首先要声明一下, 这里带大家自定义 MyBatis 分页插件, 主要是想通过这个东西让小伙伴们了解自定义 MyBatis 插件的一些条条框框, 了解整个自定义插件的流程, 分页插件并不是我们的目的, 自定义分页插件只是为了让大家的学习过程变得有趣一些而已.

接下来我们就来开启自定义分页插件之旅.

### 4.2.1 `PageRowBounds` 参数类型

首先我们需要自定义一个 `RowBounds`, 因为 `MyBatis` 原生的 `RowBounds` 是内存分页, 并且没有办法获取到总记录数 (一般分页查询的时候我们还需要获取到总记录数), 所以我们自定义 `PageRowBounds`, 对原生的 `RowBounds` 功能进行增强, 如下:

```java
public class PageRowBounds extends RowBounds {
    private Long total;

    public PageRowBounds(int offset, int limit) {
        super(offset, limit);
    }

    public PageRowBounds() {
    }

    public Long getTotal() {
        return total;
    }

    public void setTotal(Long total) {
        this.total = total;
    }
}
```

可以看到, 我们自定义的 `PageRowBounds` 中增加了 `total` 字段, 用来保存查询的总记录数.

### 4.2.2 `PageInterceptor` 拦截器

接下来我们自定义拦截器 `PageInterceptor`, 如下:

```js
@Intercepts(@Signature(
        type = Executor.class,
        method = "query",
        args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}
))
public class PageInterceptor implements Interceptor {
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object[] args = invocation.getArgs();
        MappedStatement ms = (MappedStatement) args[0];
        Object parameterObject = args[1];
        RowBounds rowBounds = (RowBounds) args[2];
        if (rowBounds != RowBounds.DEFAULT) {
            Executor executor = (Executor) invocation.getTarget();
            BoundSql boundSql = ms.getBoundSql(parameterObject);
            Field additionalParametersField = BoundSql.class.getDeclaredField("additionalParameters");
            additionalParametersField.setAccessible(true);
            Map<String, Object> additionalParameters = (Map<String, Object>) additionalParametersField.get(boundSql);
            if (rowBounds instanceof PageRowBounds) {
                MappedStatement countMs = newMappedStatement(ms, Long.class);
                CacheKey countKey = executor.createCacheKey(countMs, parameterObject, RowBounds.DEFAULT, boundSql);
                String countSql = "select count(*) from (" + boundSql.getSql() + ") temp";
                BoundSql countBoundSql = new BoundSql(ms.getConfiguration(), countSql, boundSql.getParameterMappings(), parameterObject);
                Set<String> keySet = additionalParameters.keySet();
                for (String key : keySet) {
                    countBoundSql.setAdditionalParameter(key, additionalParameters.get(key));
                }
                List<Object> countQueryResult = executor.query(countMs, parameterObject, RowBounds.DEFAULT, (ResultHandler) args[3], countKey, countBoundSql);
                Long count = (Long) countQueryResult.get(0);
                ((PageRowBounds) rowBounds).setTotal(count);
            }
            CacheKey pageKey = executor.createCacheKey(ms, parameterObject, rowBounds, boundSql);
            pageKey.update("RowBounds");
            String pageSql = boundSql.getSql() + " limit " + rowBounds.getOffset() + "," + rowBounds.getLimit();
            BoundSql pageBoundSql = new BoundSql(ms.getConfiguration(), pageSql, boundSql.getParameterMappings(), parameterObject);
            Set<String> keySet = additionalParameters.keySet();
            for (String key : keySet) {
                pageBoundSql.setAdditionalParameter(key, additionalParameters.get(key));
            }
            List list = executor.query(ms, parameterObject, RowBounds.DEFAULT, (ResultHandler) args[3], pageKey, pageBoundSql);
            return list;
        }
        //不需要分页，直接返回结果
        return invocation.proceed();
    }

    private MappedStatement newMappedStatement(MappedStatement ms, Class<Long> longClass) {
        MappedStatement.Builder builder = new MappedStatement.Builder(
                ms.getConfiguration(), ms.getId() + "_count", ms.getSqlSource(), ms.getSqlCommandType()
        );
        ResultMap resultMap = new ResultMap.Builder(ms.getConfiguration(), ms.getId(), longClass, new ArrayList<>(0)).build();
        builder.resource(ms.getResource())
                .fetchSize(ms.getFetchSize())
                .statementType(ms.getStatementType())
                .timeout(ms.getTimeout())
                .parameterMap(ms.getParameterMap())
                .resultSetType(ms.getResultSetType())
                .cache(ms.getCache())
                .flushCacheRequired(ms.isFlushCacheRequired())
                .useCache(ms.isUseCache())
                .resultMaps(Arrays.asList(resultMap));
        if (ms.getKeyProperties() != null && ms.getKeyProperties().length > 0) {
            StringBuilder keyProperties = new StringBuilder();
            for (String keyProperty : ms.getKeyProperties()) {
                keyProperties.append(keyProperty).append(",");
            }
            keyProperties.delete(keyProperties.length() - 1, keyProperties.length());
            builder.keyProperty(keyProperties.toString());
        }
        return builder.build();
    }
}
```

这是我们今天定义的核心代码, 涉及到的知识点我们来一个一个剖析.

1. 首先通过 `@Intercepts` 注解配置拦截器签名, 从 `@Signature` 的定义中我们可以看到, 拦截的是 `Executor#query` 方法, 该方法有一个重载方法, 通过 `args` 指定了方法参数, 进而锁定了重载方法, (实际上该方法的另一个重载方法我们没法拦截, 那个是 MyBatis 内部调用的, 这里不做讨论).

2. 将查询操作拦截下来之后, 接下来我们的操作主要在 `PageInterceptor#intercept` 方法中完成, 该方法的参数重包含了拦截对象的诸多信息.

3. 通过 `invocation.getArgs()` 获取拦截方法的参数, 获取到的是一个数组, 正常来说这个数组的长度为 `4`. 
    - 数组第一项, 是一个 `MappedStatement`, 我们在 `Mapper.xml` 中定义的各种操作节点和 SQL，都被封装成一个个的 `MappedStatement` 对象了; 
    - 数组第二项, 就是所拦截方法的具体参数，也就是你在 `Mapper` 接口中定义的方法参数; 
    - 数组第三项, 是一个 `RowBounds` 对象, 我们在 `Mapper` 接口中定义方法时不一定使用了 `RowBounds` 对象, 如果我们没有定义 `RowBounds` 对象, 系统会给我们提供一个默认的 `RowBounds.DEFAULT`;
    - 数组第四项, 则是一个处理返回值的 `ResultHandler`.

4. 接下来判断上一步提取到的 `rowBounds` 对象是否不为 `RowBounds.DEFAULT`, 如果为 `RowBounds.DEFAULT`, 说明用户不想分页; 如果不为 `RowBounds.DEFAULT`, 则说明用户想要分页, 如果用户不想分页, 则直接执行最后的 `return invocation.proceed();`, 让方法继续往下走就行了.

5. 如果需要进行分页, 则先从 `invocation` 对象中取出: 
    - `Executor`: 执行器; 
    - `BoundSql`: `BoundSql` 中封装了我们执行的 Sql 以及相关的参数.
    - `additionalParameters`: 通过反射取出, `BoundSql` 中保存的额外参数(如果我们使用了动态 SQL, 可能会存在该参数). 

6. 接下来判断 `rowBounds` 是否是 `PageRowBounds` 的实例. 
    - 如果是, 说明除了分页查询, 还想要查询总记录数; 
    - 如果不是, 则说明 `rowBounds` 可能是 `RowBounds` 实例, 此时只要分页即可, 不用查询总记录数.

7. 如果需要查询总记录数, 则首先调用 `newMappedStatement` 方法构造出一个新的 `MappedStatement` 对象, 这个新的 `MappedStatement` 对象的返回值是 `Long` 类型的. 然后分别创建查询的 `CacheKey`, 拼接查询的 `countSql`, 再根据 `countSql` 构建出 `countBoundSql`, 再将额外参数添加进 `countBoundSql` 中. 最后通过 `executor.query` 方法完成查询操作, 并将查询结果赋值给 `PageRowBounds` 中的 `total` 属性.

8. 接下来进行分页查询, 有了第七步的介绍之后, 分页查询就很简单了, 这里就不细说了, 唯一需要强调的是, 当我们启动了这个分页插件之后, MyBatis 原生的 `RowBounds` 内存分页会变成物理分页, 原因就在这里我们修改了查询 SQL.

9. 最后将查询结果返回.

> 注意: 在前面的代码中, 我们一共在两个地方重新组织了 SQL, 一个是查询总记录数的时候, 另一个则是分页的时候. 都是通过 `boundSql.getSql()` 获取到 `Mapper.xml` 中的 SQL 然后进行改装, 有的小伙伴在 `Mapper.xml` 中写 SQL 的时候不注意, 结尾可能加上了 `;`, 这会导致分页插件重新组装的 SQL 运行出错, 这点需要注意. 在 GitHub 上看到的其他 MyBatis 分页插件也是一样的, `Mapper.xml` 中 SQL 结尾不能有 `;`.

如此之后, 我们的分页插件就算是定义成功了.

# 5. 测试

接下来我们对我们的分页插件进行一个简单测试. 

首先我们需要在全局配置中配置分页插件, 配置方式如下:

```xml
<plugins>
    <plugin interceptor="org.javaboy.mybatis03.plugin.PageInterceptor"></plugin>
</plugins>
```

接下来我们在 Mapper 中定义查询接口:

```js
public interface UserMapper {
    List<User> getAllUsersByPage(RowBounds rowBounds);
}
```

接下来定义 `UserMapper.xml`, 如下:

```xml
<select id="getAllUsersByPage" resultType="org.javaboy.mybatis03.model.User">
    select * from user
</select>
```

最后我们进行测试:

```java
@Test
public void test3() {
    UserMapper userMapper = sqlSessionFactory.openSession().getMapper(UserMapper.class);
    List<User> list = userMapper.getAllUsersByPage(new RowBounds(1,2));
    for (User user : list) {
        System.out.println("user = " + user);
    }
}
```

这里在查询时, 我们使用了 `RowBounds` 对象, 就只会进行分页, 而不会统计总记录数. 需要注意的时, 此时的分页已经不是内存分页, 而是物理分页了, 这点我们从打印出来的 SQL 中也能看到, 如下:

```
==> Prepering: SELECT * FROM user LIMIT 1, 2
[DEBUG] method: org.apache.ibatis.logging.jdbc.BaseJdbcLogger.debug(BaseJdbcLogger.java: 137)
==> Parameters:
[DEBUG] method: org.aoache.ibatis.logging.jdbc.BaseJdbcLogger.debug(BaseJdbcLogger.java: 137)
<==     Total: 2
user = User{id=3, username='chuanshen', address='chuanshen.com', enabled=true}
user = User{id=4, username='zhangsan', address='shandong', enabled=false}
```

可以看到, 查询的时候就已经进行了分页了.

当然, 我们也可以使用 `PageRowBounds` 进行测试, 如下:

```java
@Test
public void test4() {
    UserMapper userMapper = sqlSessionFactory.openSession().getMapper(UserMapper.class);
    PageRowBounds pageRowBounds = new PageRowBounds(1, 2);
    List<User> list = userMapper.getAllUsersByPage(pageRowBounds);
    for (User user : list) {
        System.out.println("user = " + user);
    }
    System.out.println("pageRowBounds.getTotal() = " + pageRowBounds.getTotal());
}
```

此时通过 `pageRowBounds.getTotal()` 方法我们就可以获取到总记录数.