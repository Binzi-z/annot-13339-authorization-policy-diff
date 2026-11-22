"""错误类型定义。"""


class AuthzError(Exception):
    """本工具所有错误的基类。"""


class PolicyValidationError(AuthzError):
    """策略配置非法。

    评估与差异计算入口都会先做整体校验；只要配置非法，立即抛出本异常，
    不会返回任何放行判断，也不会产出差异报告。
    """

    def __init__(self, errors):
        if isinstance(errors, str):
            errors = [errors]
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


class InternalError(AuthzError):
    """引擎内部不变量被破坏（例如见证自检失败）。"""
