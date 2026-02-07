#pragma once
#include "../config.h"

// fixed-width types and type traits without STL/CRT dependencies
#pragma warning(push)
#pragma warning(disable: 4310) // cast truncates constant value
#pragma warning(disable: 4296) // '<': expression is always false (unsigned is_signed check)

namespace kernelcloak {

using uint8_t  = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;
using int8_t   = signed char;
using int16_t  = signed short;
using int32_t  = signed int;
using int64_t  = signed long long;
using size_t   = decltype(sizeof(0));
using uintptr_t = size_t;
using intptr_t  = long long;
using ptrdiff_t = long long;
using nullptr_t = decltype(nullptr);

namespace detail {

// integral_constant
template<typename T, T V>
struct integral_constant {
    static constexpr T value = V;
    using value_type = T;
    using type = integral_constant;
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; }
};

using true_type  = integral_constant<bool, true>;
using false_type = integral_constant<bool, false>;

// remove_cv
template<typename T> struct remove_const          { using type = T; };
template<typename T> struct remove_const<const T>  { using type = T; };

template<typename T> struct remove_volatile             { using type = T; };
template<typename T> struct remove_volatile<volatile T>  { using type = T; };

template<typename T> struct remove_cv {
    using type = typename remove_const<typename remove_volatile<T>::type>::type;
};
template<typename T> using remove_cv_t = typename remove_cv<T>::type;

// remove_reference
template<typename T> struct remove_reference       { using type = T; };
template<typename T> struct remove_reference<T&>   { using type = T; };
template<typename T> struct remove_reference<T&&>  { using type = T; };
template<typename T> using remove_reference_t = typename remove_reference<T>::type;

// remove_extent
template<typename T> struct remove_extent                { using type = T; };
template<typename T> struct remove_extent<T[]>           { using type = T; };
template<typename T, size_t N> struct remove_extent<T[N]> { using type = T; };

// remove_pointer
template<typename T> struct remove_pointer                    { using type = T; };
template<typename T> struct remove_pointer<T*>                { using type = T; };
template<typename T> struct remove_pointer<T* const>          { using type = T; };
template<typename T> struct remove_pointer<T* volatile>       { using type = T; };
template<typename T> struct remove_pointer<T* const volatile> { using type = T; };

// add_pointer
template<typename T> struct add_pointer { using type = typename remove_reference<T>::type*; };
template<typename T> using add_pointer_t = typename add_pointer<T>::type;

// is_same
template<typename T, typename U> struct is_same : false_type {};
template<typename T> struct is_same<T, T> : true_type {};
template<typename T, typename U> static constexpr bool is_same_v = is_same<T, U>::value;

// is_void
template<typename T> struct is_void : is_same<remove_cv_t<T>, void> {};
template<typename T> static constexpr bool is_void_v = is_void<T>::value;

// is_nullptr
template<typename T> struct is_null_pointer : is_same<remove_cv_t<T>, nullptr_t> {};

// is_integral
template<typename T> struct is_integral_impl : false_type {};
template<> struct is_integral_impl<bool>               : true_type {};
template<> struct is_integral_impl<char>               : true_type {};
template<> struct is_integral_impl<signed char>        : true_type {};
template<> struct is_integral_impl<unsigned char>      : true_type {};
#ifdef _NATIVE_WCHAR_T_DEFINED
template<> struct is_integral_impl<wchar_t>            : true_type {};
#endif
template<> struct is_integral_impl<char16_t>           : true_type {};
template<> struct is_integral_impl<char32_t>           : true_type {};
template<> struct is_integral_impl<short>              : true_type {};
template<> struct is_integral_impl<unsigned short>     : true_type {};
template<> struct is_integral_impl<int>                : true_type {};
template<> struct is_integral_impl<unsigned int>       : true_type {};
template<> struct is_integral_impl<long>               : true_type {};
template<> struct is_integral_impl<unsigned long>      : true_type {};
template<> struct is_integral_impl<long long>          : true_type {};
template<> struct is_integral_impl<unsigned long long> : true_type {};

template<typename T> struct is_integral : is_integral_impl<remove_cv_t<T>> {};
template<typename T> static constexpr bool is_integral_v = is_integral<T>::value;

// is_floating_point
template<typename T> struct is_floating_point_impl : false_type {};
template<> struct is_floating_point_impl<float>       : true_type {};
template<> struct is_floating_point_impl<double>      : true_type {};
template<> struct is_floating_point_impl<long double> : true_type {};

template<typename T> struct is_floating_point : is_floating_point_impl<remove_cv_t<T>> {};
template<typename T> static constexpr bool is_floating_point_v = is_floating_point<T>::value;

// is_arithmetic
template<typename T> struct is_arithmetic : integral_constant<bool,
    is_integral<T>::value || is_floating_point<T>::value> {};
template<typename T> static constexpr bool is_arithmetic_v = is_arithmetic<T>::value;

// is_pointer
template<typename T> struct is_pointer_impl : false_type {};
template<typename T> struct is_pointer_impl<T*> : true_type {};

template<typename T> struct is_pointer : is_pointer_impl<remove_cv_t<T>> {};
template<typename T> static constexpr bool is_pointer_v = is_pointer<T>::value;

// is_array
template<typename T> struct is_array : false_type {};
template<typename T> struct is_array<T[]> : true_type {};
template<typename T, size_t N> struct is_array<T[N]> : true_type {};
template<typename T> static constexpr bool is_array_v = is_array<T>::value;

// is_const / is_volatile
template<typename T> struct is_const : false_type {};
template<typename T> struct is_const<const T> : true_type {};
template<typename T> static constexpr bool is_const_v = is_const<T>::value;

template<typename T> struct is_volatile : false_type {};
template<typename T> struct is_volatile<volatile T> : true_type {};
template<typename T> static constexpr bool is_volatile_v = is_volatile<T>::value;

// is_reference
template<typename T> struct is_lvalue_reference : false_type {};
template<typename T> struct is_lvalue_reference<T&> : true_type {};

template<typename T> struct is_rvalue_reference : false_type {};
template<typename T> struct is_rvalue_reference<T&&> : true_type {};

template<typename T> struct is_reference : integral_constant<bool,
    is_lvalue_reference<T>::value || is_rvalue_reference<T>::value> {};

// is_function (simplified - detects most common calling conventions)
template<typename T> struct is_function : false_type {};
template<typename R, typename... A> struct is_function<R(A...)> : true_type {};
template<typename R, typename... A> struct is_function<R(A..., ...)> : true_type {};
// const/volatile/ref qualified
template<typename R, typename... A> struct is_function<R(A...) const> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) volatile> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) const volatile> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) &> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) const &> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) volatile &> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) const volatile &> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) &&> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) const &&> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) volatile &&> : true_type {};
template<typename R, typename... A> struct is_function<R(A...) const volatile &&> : true_type {};
// noexcept variants
template<typename R, typename... A> struct is_function<R(A...) noexcept> : true_type {};
template<typename R, typename... A> struct is_function<R(A..., ...) noexcept> : true_type {};

// conditional
template<bool B, typename T, typename F> struct conditional { using type = T; };
template<typename T, typename F> struct conditional<false, T, F> { using type = F; };
template<bool B, typename T, typename F> using conditional_t = typename conditional<B, T, F>::type;

// enable_if
template<bool B, typename T = void> struct enable_if {};
template<typename T> struct enable_if<true, T> { using type = T; };
template<bool B, typename T = void> using enable_if_t = typename enable_if<B, T>::type;

// add_const / add_volatile / add_cv
template<typename T> struct add_const    { using type = const T; };
template<typename T> struct add_volatile { using type = volatile T; };
template<typename T> struct add_cv       { using type = const volatile T; };
template<typename T> using add_const_t    = typename add_const<T>::type;
template<typename T> using add_volatile_t = typename add_volatile<T>::type;
template<typename T> using add_cv_t       = typename add_cv<T>::type;

// add_lvalue_reference / add_rvalue_reference
namespace ref_detail {
    template<typename T> struct type_identity { using type = T; };
    template<typename T> auto try_add_lvalue_ref(int) -> type_identity<T&>;
    template<typename T> auto try_add_lvalue_ref(...) -> type_identity<T>;
    template<typename T> auto try_add_rvalue_ref(int) -> type_identity<T&&>;
    template<typename T> auto try_add_rvalue_ref(...) -> type_identity<T>;
}
template<typename T> struct add_lvalue_reference : decltype(ref_detail::try_add_lvalue_ref<T>(0)) {};
template<typename T> struct add_rvalue_reference : decltype(ref_detail::try_add_rvalue_ref<T>(0)) {};
template<typename T> using add_lvalue_reference_t = typename add_lvalue_reference<T>::type;
template<typename T> using add_rvalue_reference_t = typename add_rvalue_reference<T>::type;

// decay
template<typename T>
struct decay {
private:
    using U = remove_reference_t<T>;
public:
    using type = conditional_t<
        is_array<U>::value,
        typename remove_extent<U>::type*,
        conditional_t<
            is_function<U>::value,
            typename add_pointer<U>::type,
            remove_cv_t<U>
        >
    >;
};
template<typename T> using decay_t = typename decay<T>::type;

// is_unsigned / is_signed
template<typename T, bool = is_arithmetic_v<T>>
struct is_unsigned_impl : integral_constant<bool, T(0) < T(-1)> {};
template<typename T> struct is_unsigned_impl<T, false> : false_type {};
template<typename T> struct is_unsigned : is_unsigned_impl<T> {};
template<typename T> static constexpr bool is_unsigned_v = is_unsigned<T>::value;

template<typename T, bool = is_arithmetic_v<T>>
struct is_signed_impl : integral_constant<bool, T(-1) < T(0)> {};
template<typename T> struct is_signed_impl<T, false> : false_type {};
template<typename T> struct is_signed : is_signed_impl<T> {};
template<typename T> static constexpr bool is_signed_v = is_signed<T>::value;

// make_unsigned / make_signed
template<typename T> struct make_unsigned;
template<> struct make_unsigned<char>               { using type = unsigned char; };
template<> struct make_unsigned<signed char>        { using type = unsigned char; };
template<> struct make_unsigned<unsigned char>      { using type = unsigned char; };
template<> struct make_unsigned<short>              { using type = unsigned short; };
template<> struct make_unsigned<unsigned short>     { using type = unsigned short; };
template<> struct make_unsigned<int>                { using type = unsigned int; };
template<> struct make_unsigned<unsigned int>       { using type = unsigned int; };
template<> struct make_unsigned<long>               { using type = unsigned long; };
template<> struct make_unsigned<unsigned long>      { using type = unsigned long; };
template<> struct make_unsigned<long long>          { using type = unsigned long long; };
template<> struct make_unsigned<unsigned long long> { using type = unsigned long long; };
template<typename T> using make_unsigned_t = typename make_unsigned<T>::type;

template<typename T> struct make_signed;
template<> struct make_signed<char>               { using type = signed char; };
template<> struct make_signed<signed char>        { using type = signed char; };
template<> struct make_signed<unsigned char>      { using type = signed char; };
template<> struct make_signed<short>              { using type = short; };
template<> struct make_signed<unsigned short>     { using type = short; };
template<> struct make_signed<int>                { using type = int; };
template<> struct make_signed<unsigned int>       { using type = int; };
template<> struct make_signed<long>               { using type = long; };
template<> struct make_signed<unsigned long>      { using type = long; };
template<> struct make_signed<long long>          { using type = long long; };
template<> struct make_signed<unsigned long long> { using type = long long; };
template<typename T> using make_signed_t = typename make_signed<T>::type;

// void_t
template<typename...> using void_t = void;

// conjunction / disjunction / negation
template<typename...> struct conjunction : true_type {};
template<typename B1> struct conjunction<B1> : B1 {};
template<typename B1, typename... Bn>
struct conjunction<B1, Bn...> : conditional_t<bool(B1::value), conjunction<Bn...>, B1> {};

template<typename...> struct disjunction : false_type {};
template<typename B1> struct disjunction<B1> : B1 {};
template<typename B1, typename... Bn>
struct disjunction<B1, Bn...> : conditional_t<bool(B1::value), B1, disjunction<Bn...>> {};

template<typename B>
struct negation : integral_constant<bool, !bool(B::value)> {};

// integer_sequence
template<typename T, T... Is>
struct integer_sequence {
    using value_type = T;
    static constexpr size_t size() noexcept { return sizeof...(Is); }
};

template<size_t... Is>
using index_sequence = integer_sequence<size_t, Is...>;

#ifdef _MSC_VER
// MSVC provides __make_integer_seq as a builtin - avoids deep recursion
// and works around MSVC issues with dependent non-type template parameter
// partial specializations
template<typename T, T N>
using make_integer_sequence = __make_integer_seq<integer_sequence, T, N>;
#else
namespace seq_detail {
    template<typename T, T N, T... Is>
    struct make_seq_impl : make_seq_impl<T, N - 1, N - 1, Is...> {};

    template<typename T, T... Is>
    struct make_seq_impl<T, static_cast<T>(0), Is...> {
        using type = integer_sequence<T, Is...>;
    };
}

template<typename T, T N>
using make_integer_sequence = typename seq_detail::make_seq_impl<T, N>::type;
#endif

template<size_t N>
using make_index_sequence = make_integer_sequence<size_t, N>;

template<typename... T>
using index_sequence_for = make_index_sequence<sizeof...(T)>;

// is_trivially_copyable - compiler intrinsic based
template<typename T> struct is_trivially_copyable
    : integral_constant<bool, __is_trivially_copyable(T)> {};
template<typename T> static constexpr bool is_trivially_copyable_v = is_trivially_copyable<T>::value;

// is_trivially_destructible
template<typename T> struct is_trivially_destructible
    : integral_constant<bool, __is_trivially_destructible(T)> {};

// alignment_of
template<typename T> struct alignment_of : integral_constant<size_t, alignof(T)> {};

} // namespace detail

// pull commonly used traits into core namespace
namespace core {
    using detail::integral_constant;
    using detail::true_type;
    using detail::false_type;
    using detail::is_same;
    using detail::is_same_v;
    using detail::is_integral;
    using detail::is_integral_v;
    using detail::is_pointer;
    using detail::is_pointer_v;
    using detail::is_array;
    using detail::is_array_v;
    using detail::is_void;
    using detail::is_void_v;
    using detail::is_arithmetic;
    using detail::is_floating_point;
    using detail::is_const;
    using detail::is_volatile;
    using detail::is_reference;
    using detail::is_unsigned;
    using detail::is_signed;
    using detail::is_trivially_copyable;
    using detail::is_trivially_destructible;
    using detail::enable_if;
    using detail::enable_if_t;
    using detail::conditional;
    using detail::conditional_t;
    using detail::remove_cv;
    using detail::remove_cv_t;
    using detail::remove_reference;
    using detail::remove_reference_t;
    using detail::remove_extent;
    using detail::remove_pointer;
    using detail::add_pointer;
    using detail::add_pointer_t;
    using detail::add_const;
    using detail::add_volatile;
    using detail::add_cv;
    using detail::add_lvalue_reference;
    using detail::add_rvalue_reference;
    using detail::decay;
    using detail::decay_t;
    using detail::make_unsigned;
    using detail::make_unsigned_t;
    using detail::make_signed;
    using detail::make_signed_t;
    using detail::void_t;
    using detail::conjunction;
    using detail::disjunction;
    using detail::negation;
    using detail::integer_sequence;
    using detail::index_sequence;
    using detail::make_integer_sequence;
    using detail::make_index_sequence;
    using detail::index_sequence_for;
}

// move / forward - must be in global-reachable scope for the library
namespace detail {

template<typename T>
constexpr remove_reference_t<T>&& kc_move(T&& t) noexcept {
    return static_cast<remove_reference_t<T>&&>(t);
}

template<typename T>
constexpr T&& kc_forward(remove_reference_t<T>& t) noexcept {
    return static_cast<T&&>(t);
}

template<typename T>
constexpr T&& kc_forward(remove_reference_t<T>&& t) noexcept {
    static_assert(!is_lvalue_reference<T>::value, "cannot forward rvalue as lvalue");
    return static_cast<T&&>(t);
}

// exchange replacement
template<typename T, typename U = T>
KC_FORCEINLINE T kc_exchange(T& obj, U&& new_value) noexcept {
    T old = kc_move(obj);
    obj = kc_forward<U>(new_value);
    return old;
}

} // namespace detail

} // namespace kernelcloak

#pragma warning(pop)
