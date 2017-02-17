//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BEAST_HTTP_NEW_PARSER_HPP
#define BEAST_HTTP_NEW_PARSER_HPP

#include <beast/http/message.hpp>
#include <beast/http/new_basic_parser.hpp>
#include <beast/http/detail/new_parser.hpp>
#include <array>
#include <type_traits>
#include <utility>

namespace beast {
namespace http {

template<bool isRequest>
class new_parser
    : public new_basic_parser<isRequest,
        new_parser<isRequest>>
    , private detail::new_parser_base
{
    using impl_type = typename std::conditional<
        isRequest, req_impl_base, res_impl_base>::type;

    std::unique_ptr<impl_type> p_;

public:
    /// `true` if this parser parses requests, `false` for responses.
    static bool constexpr is_request = isRequest;

    /// Destructor
    ~new_parser();

    /// Constructor
    template<class Fields>
    new_parser(header<isRequest, Fields>& m);

    /// Constructor
    template<class Body, class Fields>
    new_parser(message<isRequest, Body, Fields>& m);

    /** Move constructor.

        After the move, the only valid operation
        on the moved-from object is destruction.
    */
    new_parser(new_parser&& other) = default;

    /// Copy constructor (disallowed)
    new_parser(new_parser const&) = delete;

    /// Move assignment (disallowed)
    new_parser& operator=(new_parser&&) = delete;

    /// Copy assignment (disallowed)
    new_parser& operator=(new_parser const&) = delete;

private:
    friend class new_basic_parser<isRequest, new_parser>;

    impl_type&
    impl()
    {
        return *p_.get();
    }

    template<class Fields>
    void
    construct(header<true, Fields>& h)
    {
        split(true);
        using type = req_h_impl<Fields>;
        p_.reset(new type{h});
    }

    template<class Fields>
    void
    construct(header<false, Fields>& h)
    {
        split(true);
        using type = res_h_impl<Fields>;
        p_.reset(new type{h});
    }

    template<class Body, class Fields>
    void
    construct(message<true, Body, Fields>& m)
    {
        split(false);
        using type = req_impl<Body, Fields>;
        p_.reset(new type{m});
    }

    template<class Body, class Fields>
    void
    construct(message<false, Body, Fields>& m)
    {
        split(false);
        using type = res_impl<Body, Fields>;
        p_.reset(new type{m});
    }

    void
    on_request(boost::string_ref const& method,
        boost::string_ref const& path,
            int version, error_code&)
    {
        impl().on_req(method, path, version);
    }

    void
    on_response(int status,
        boost::string_ref const& reason,
            int version, error_code&)
    {
        impl().on_res(status, reason, version);
    }

    void
    on_field(boost::string_ref const& name,
        boost::string_ref const& value,
            error_code&)
    {
        impl().on_field(name, value);
    }

    void
    on_header(error_code& ec)
    {
        impl().on_header(ec);
    }

    void
    on_chunk(std::uint64_t length,
        boost::string_ref const& ext,
            error_code&)
    {
    }

    void
    on_body(boost::string_ref const& data,
        error_code& ec)
    {
        impl().on_body(data, ec);
    }

    void
    on_done(error_code& ec)
    {
        impl().on_done(ec);
    }
};

template<bool isRequest>
new_parser<isRequest>::
~new_parser()
{
    impl().~impl_type();
}

template<bool isRequest>
template<class Fields>
new_parser<isRequest>::
new_parser(header<isRequest, Fields>& m)
{
    construct(m);
}

template<bool isRequest>
template<class Body, class Fields>
new_parser<isRequest>::
new_parser(message<isRequest, Body, Fields>& m)
{
    construct(m);
}

} // http
} // beast

#endif
